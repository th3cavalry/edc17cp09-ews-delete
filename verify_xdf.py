import xml.etree.ElementTree as ET, json, os
os.chdir("/home/brandon/Documents/EDC17CP09")
tree = ET.parse("EDC17CP09_M57_0281017487.xdf")
r = tree.getroot()
tabs = r.findall(".//XDFTABLE")
print("XDF parses OK, XDFTABLE count:", len(tabs))

scan = json.load(open("scan_mpc.json"))
t = scan["tables"][0]
print("scan tables[0]: off %s cols %d rows %d" % (hex(t["offset"]), t["cols"], t["rows"]))

# cross check: every XDFTABLE address should exist in the scan table list
offs_xdf = set()
for x in tabs:
    ea = x.find(".//XDFAXIS")
    za = x.find(".//XDFAXIS[@id=\"z\"]")
    if za is not None:
        em = za.find("EMBEDDEDDATA")
        if em is not None and em.get("mmedaddress"):
            offs_xdf.add(em.get("mmedaddress"))
offs_scan = set(hex(t["offset"]) for t in scan["tables"])
print("XDF table-data offsets sample:", sorted(offs_xdf)[:5])
print("scan offsets sample:", sorted(offs_scan)[:5])
