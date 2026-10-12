import re
import xml.etree.ElementTree as ET

from defusedxml.ElementTree import fromstring

FIELDS = ("name", "office", "mobile", "other")
XML_FIELDS = ("display_name", "office_number", "mobile_number", "other_number")


def validate(row):
    values = tuple(str(row.get(k, "")).strip() for k in FIELDS)
    if not values[0] or len(values[0]) > 100:
        raise ValueError("A name of 1–100 characters is required.")
    if not any(values[1:]):
        raise ValueError("Enter at least one phone number.")
    if any(len(v) > 64 or (v and not re.fullmatch(r"[0-9+*#(), .\-]+", v)) for v in values[1:]):
        raise ValueError("Numbers can contain digits, spaces, +, *, #, commas, dots and brackets.")
    if any(any(ord(c) < 32 for c in v) for v in values):
        raise ValueError("Control characters are not allowed.")
    return values


def parse_xml(content):
    if len(content) > 2_000_000:
        raise ValueError("Directory file is too large.")
    # Older T46S firmware exports two sibling elements without a document root.
    fragment = re.sub(rb"^\s*<\?xml[^?]*\?>", b"", content).lstrip()
    if fragment.startswith(b"<root_group"):
        root = fromstring(b"<vp_contact>" + fragment + b"</vp_contact>")
        if [child.tag for child in root] != ["root_group", "root_contact"]:
            raise ValueError("Use a Yealink local directory XML export.")
    else:
        root = fromstring(content)
    if root.tag != "vp_contact":
        raise ValueError("Use a Yealink local directory XML export.")
    items = root.findall("./root_contact/contact")
    if len(items) > 1000:
        raise ValueError("The directory can contain at most 1,000 contacts.")
    return [dict(zip(FIELDS, (item.get(k, "") for k in XML_FIELDS))) for item in items]


def xml_for(rows):
    root = ET.Element("vp_contact")
    groups = ET.SubElement(root, "root_group")
    ET.SubElement(groups, "group", display_name="All Contacts")
    ET.SubElement(groups, "group", display_name="Blocklist")
    contacts = ET.SubElement(root, "root_contact")
    for row in rows:
        attributes = dict(zip(XML_FIELDS, (row[k] for k in FIELDS)))
        attributes.update(line="-1", ring="Auto", group_id_name="All Contacts")
        ET.SubElement(contacts, "contact", attributes)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def canonical(rows):
    # Firmware may insert spacing into phone numbers. Compare contact content,
    # including duplicates, without relying on order or serializer formatting.
    return sorted(
        tuple(
            str(r.get(k, "")).strip()
            if k == "name"
            else re.sub(r"[\s().\-]", "", str(r.get(k, "")))
            for k in FIELDS
        )
        for r in rows
    )
