"""Proxmox VE and PBS API clients."""
from __future__ import annotations

import time

import requests

requests.packages.urllib3.disable_warnings()


class ProxmoxClient:
    def __init__(self, api_host: str, token: str, verify_tls: bool = True):
        self.api_host = api_host.rstrip("/")
        self.headers = {"Authorization": f"PVEAPIToken={token}"}
        self.verify_tls = verify_tls

    def trigger_backup(self, node: str, vmid: int, storage: str) -> str:
        resp = requests.post(
            f"{self.api_host}/api2/json/nodes/{node}/vzdump",
            headers=self.headers,
            data={"vmid": vmid, "storage": storage, "mode": "snapshot"},
            verify=self.verify_tls,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def wait_for_task(self, node: str, upid: str, *, poll_interval: float = 5.0,
                       timeout: float = 3600.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            resp = requests.get(
                f"{self.api_host}/api2/json/nodes/{node}/tasks/{upid}/status",
                headers=self.headers,
                verify=self.verify_tls,
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()["data"]
            if data["status"] == "stopped":
                return data.get("exitstatus") == "OK"
            time.sleep(poll_interval)
        raise TimeoutError(f"Proxmox task {upid} did not finish within {timeout}s")

    def list_nodes(self) -> list[str]:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return [n["node"] for n in resp.json()["data"]]

    def list_disks(self, node: str) -> list[dict]:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/{node}/disks/list",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def get_disk_smart(self, node: str, device: str) -> dict:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/{node}/disks/smart",
            headers=self.headers,
            params={"disk": device},
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def recent_vzdump_tasks(self, node: str, *, limit: int = 5) -> list[dict]:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/{node}/tasks",
            headers=self.headers,
            params={"typefilter": "vzdump", "limit": limit},
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def last_vm_backup(self, node: str, vmid: int) -> dict | None:
        tasks = self.recent_vzdump_tasks(node, limit=30)
        matches = [t for t in tasks if t.get("id") == str(vmid)]
        if not matches:
            return None
        return max(matches, key=lambda t: t.get("starttime", 0))

    def node_status(self, node: str) -> dict:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/{node}/status",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def node_rrd_data(self, node: str, timeframe: str = "week") -> list[dict]:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/{node}/rrddata",
            headers=self.headers,
            params={"timeframe": timeframe, "cf": "AVERAGE"},
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def node_for_vmid(self, vmid: int) -> str:
        resp = requests.get(
            f"{self.api_host}/api2/json/cluster/resources",
            headers=self.headers,
            params={"type": "vm"},
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        for res in resp.json()["data"]:
            if res.get("vmid") == vmid:
                return res["node"]
        raise ValueError(f"VMID {vmid} not found in cluster resources")

    def vm_type_for_vmid(self, vmid: int) -> str:
        resp = requests.get(
            f"{self.api_host}/api2/json/cluster/resources",
            headers=self.headers,
            params={"type": "vm"},
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        for res in resp.json()["data"]:
            if res.get("vmid") == vmid:
                return res["type"]
        raise ValueError(f"VMID {vmid} not found in cluster resources")

    def cluster_vm_resources(self) -> list[dict]:
        resp = requests.get(
            f"{self.api_host}/api2/json/cluster/resources",
            headers=self.headers,
            params={"type": "vm"},
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def vm_locked_for_backup(self, node: str, vmid: int, vm_type: str = "qemu") -> bool:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/{node}/{vm_type}/{vmid}/status/current",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"].get("lock") == "backup"

    def wait_for_vm_unlocked(self, node: str, vmid: int, *, vm_type: str = "qemu",
                              poll_interval: float = 15.0,
                              timeout: float = 1800.0) -> None:
        deadline = time.monotonic() + timeout
        while self.vm_locked_for_backup(node, vmid, vm_type):
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"VM {vmid} on {node} still locked for backup after waiting {timeout}s"
                )
            time.sleep(poll_interval)

    def vm_power_status(self, node: str, vmid: int, vm_type: str = "qemu") -> str:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/{node}/{vm_type}/{vmid}/status/current",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]["status"]

    def shutdown_vm(self, node: str, vmid: int, vm_type: str = "qemu") -> None:
        resp = requests.post(
            f"{self.api_host}/api2/json/nodes/{node}/{vm_type}/{vmid}/status/shutdown",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=30,
        )
        resp.raise_for_status()

    def start_vm(self, node: str, vmid: int, vm_type: str = "qemu") -> None:
        resp = requests.post(
            f"{self.api_host}/api2/json/nodes/{node}/{vm_type}/{vmid}/status/start",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=30,
        )
        resp.raise_for_status()


class PBSClient:
    def __init__(self, api_host: str, token: str, verify_tls: bool = True):
        self.api_host = api_host.rstrip("/")
        self.headers = {"Authorization": f"PBSAPIToken={token}"}
        self.verify_tls = verify_tls

    def datastore_status(self, datastore: str) -> dict:
        resp = requests.get(
            f"{self.api_host}/api2/json/admin/datastore/{datastore}/status",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def list_disks(self) -> list[dict]:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/localhost/disks/list",
            headers=self.headers,
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def recent_tasks(self, *, limit: int = 20, typefilter: str | None = None) -> list[dict]:
        resp = requests.get(
            f"{self.api_host}/api2/json/nodes/localhost/tasks",
            headers=self.headers,
            params={"limit": limit, **({"typefilter": typefilter} if typefilter else {})},
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"]

    def last_vm_snapshot(self, datastore: str, vmid: int, backup_type: str = "vm") -> dict | None:
        resp = requests.get(
            f"{self.api_host}/api2/json/admin/datastore/{datastore}/snapshots",
            headers=self.headers,
            params={"backup-type": backup_type, "backup-id": str(vmid)},
            verify=self.verify_tls,
            timeout=15,
        )
        resp.raise_for_status()
        snapshots = resp.json()["data"]
        if not snapshots:
            return None
        return max(snapshots, key=lambda s: s.get("backup-time", 0))
