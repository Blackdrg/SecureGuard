"""
System Telemetry Router - Real system data from psutil
"""
import psutil
import platform
import socket
import uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException
from typing import Dict, List, Any
import os

router = APIRouter()


def get_device_id() -> str:
    """Get unique device identifier"""
    try:
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 8*6, 8)][::-1])
        return f"DG-{mac.replace(':', '').upper()[:12]}"
    except:
        return f"DG-{socket.gethostname().upper()}"


@router.get("/system-info")
async def get_system_info() -> Dict[str, Any]:
    """Get real system information"""
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        return {
            "device_id": get_device_id(),
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "boot_time": boot_time.isoformat(),
            "uptime_seconds": int(uptime.total_seconds()),
            "uptime_str": str(uptime).split('.')[0]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cpu")
async def get_cpu_info() -> Dict[str, Any]:
    """Get real CPU information and usage"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1, percpu=False)
        cpu_percent_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
        cpu_freq = psutil.cpu_freq()
        
        return {
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "current_freq_mhz": cpu_freq.current if cpu_freq else 0,
            "min_freq_mhz": cpu_freq.min if cpu_freq else 0,
            "max_freq_mhz": cpu_freq.max if cpu_freq else 0,
            "usage_percent": cpu_percent,
            "usage_per_core": cpu_percent_per_core,
            "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/memory")
async def get_memory_info() -> Dict[str, Any]:
    """Get real memory information"""
    try:
        virtual = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            "virtual": {
                "total_bytes": virtual.total,
                "available_bytes": virtual.available,
                "used_bytes": virtual.used,
                "free_bytes": virtual.free,
                "usage_percent": virtual.percent
            },
            "swap": {
                "total_bytes": swap.total,
                "used_bytes": swap.used,
                "free_bytes": swap.free,
                "usage_percent": swap.percent
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/disk")
async def get_disk_info() -> Dict[str, Any]:
    """Get real disk information"""
    try:
        disks = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "filesystem": partition.fstype,
                    "options": partition.opts,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "usage_percent": usage.percent
                })
            except:
                continue
        
        # Get disk I/O stats
        io_counters = psutil.disk_io_counters()
        if io_counters:
            disk_io = {
                "read_count": io_counters.read_count,
                "write_count": io_counters.write_count,
                "read_bytes": io_counters.read_bytes,
                "write_bytes": io_counters.write_bytes,
                "read_time_ms": io_counters.read_time,
                "write_time_ms": io_counters.write_time
            }
        else:
            disk_io = None
            
        return {
            "disks": disks,
            "io": disk_io
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/network")
async def get_network_info() -> Dict[str, Any]:
    """Get real network information"""
    try:
        net_io = psutil.net_io_counters()
        connections = psutil.net_connections()
        
        # Get active connections by status
        conn_by_status = {}
        for conn in connections:
            status = conn.status if conn.status else "UNKNOWN"
            conn_by_status[status] = conn_by_status.get(status, 0) + 1
        
        # Get per-interface stats
        interfaces = {}
        for iface, addrs in psutil.net_if_addrs().items():
            try:
                stats = psutil.net_if_stats()
                if iface in stats:
                    interfaces[iface] = {
                        "is_up": stats[iface].isup,
                        "speed_mbps": stats[iface].speed,
                        "mtu": stats[iface].mtu
                    }
            except:
                pass
        
        return {
            "total_bytes_sent": net_io.bytes_sent,
            "total_bytes_recv": net_io.bytes_recv,
            "total_packets_sent": net_io.packets_sent,
            "total_packets_recv": net_io.packets_recv,
            "total_errors_in": net_io.errin,
            "total_errors_out": net_io.errout,
            "total_drops_in": net_io.dropin,
            "total_drops_out": net_io.dropout,
            "connections_by_status": conn_by_status,
            "total_connections": len(connections),
            "interfaces": interfaces
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/processes")
async def get_processes() -> List[Dict[str, Any]]:
    """Get real running processes"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'create_time', 'num_threads']):
            try:
                pinfo = proc.info
                processes.append({
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "username": pinfo['username'],
                    "status": pinfo['status'],
                    "cpu_percent": pinfo['cpu_percent'] or 0,
                    "memory_percent": pinfo['memory_percent'] or 0,
                    "create_time": pinfo['create_time'],
                    "num_threads": pinfo['num_threads']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by CPU usage
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        return processes[:50]  # Top 50 processes
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/battery")
async def get_battery_info() -> Dict[str, Any]:
    """Get battery information"""
    try:
        battery = psutil.sensors_battery()
        if battery:
            return {
                "percent": battery.percent,
                "seconds_left": battery.secsleft,
                "power_plugged": battery.power_plugged
            }
        return {"percent": None, "seconds_left": None, "power_plugged": None}
    except:
        return {"percent": None, "seconds_left": None, "power_plugged": None}


@router.get("/temperature")
async def get_temperature() -> Dict[str, Any]:
    """Get temperature readings"""
    try:
        temps = psutil.sensors_temperatures()
        return {"temperatures": temps}
    except:
        return {"temperatures": {}}


@router.get("/all")
async def get_all_telemetry() -> Dict[str, Any]:
    """Get all system telemetry combined"""
    try:
        return {
            "timestamp": datetime.now().isoformat(),
            "device_id": get_device_id(),
            "system": await get_system_info(),
            "cpu": await get_cpu_info(),
            "memory": await get_memory_info(),
            "disk": await get_disk_info(),
            "network": await get_network_info(),
            "processes": await get_processes()[:20],
            "battery": await get_battery_info()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/security-status")
async def get_security_status() -> Dict[str, Any]:
    """Get security-related system status"""
    try:
        # Get critical processes
        critical_processes = ['svchost.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe']
        critical_status = []
        
        for proc in psutil.process_iter(['name', 'status', 'cpu_percent']):
            try:
                if proc.info['name'].lower() in critical_processes:
                    critical_status.append({
                        "name": proc.info['name'],
                        "status": proc.info['status'],
                        "cpu": proc.info['cpu_percent']
                    })
            except:
                continue
        
        # Get memory usage for security context
        mem = psutil.virtual_memory()
        
        return {
            "timestamp": datetime.now().isoformat(),
            "device_id": get_device_id(),
            "memory_usage_percent": mem.percent,
            "critical_processes": critical_status,
            "suspicious_memory_high": mem.percent > 95,
            "swap_usage_percent": psutil.swap_memory().percent
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

