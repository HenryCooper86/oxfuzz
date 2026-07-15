"""Stable values shared by the sidecar contract and operations."""

SCHEMA_VERSION = 1
ADAPTER_VERSION = "0.1.0"
PROTOCOLS = (
    "can",
    "can_fd",
    "iso_tp",
    "uds",
    "gmlan",
    "some_ip",
    "some_ip_sd",
    "do_ip",
    "obd",
    "ccp",
    "xcp",
    "bmw_hsfz",
    "sec_oc",
)
MODES = ("offline_pcap", "virtual_can", "physical_bench")
