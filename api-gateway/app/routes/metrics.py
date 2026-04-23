import ipaddress
from fastapi import APIRouter, Response, Request, HTTPException, status
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

router = APIRouter()

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def _is_internal_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False

@router.get("/metrics")
def metrics(request: Request):
    if not _is_internal_ip(request.client.host):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access restricted to internal network")
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
