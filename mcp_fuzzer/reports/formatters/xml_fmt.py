"""XML formatter implementation."""

from __future__ import annotations

from typing import Any

from .common import normalize_report_data


class XMLFormatter:
    """Handles XML formatting for reports."""

    def save_xml_report(
        self,
        report_data: dict[str, Any] | Any,
        filename: str,
    ):
        from xml.dom import minidom
        from xml.etree.ElementTree import Element, SubElement, tostring

        data = normalize_report_data(report_data)
        root = Element("mcp-fuzzer-report")

        if "metadata" in data:
            metadata_elem = SubElement(root, "metadata")
            for key, value in data["metadata"].items():
                SubElement(metadata_elem, key).text = str(value)

        if "tool_results" in data:
            tools_elem = SubElement(root, "tool-results")
            for tool_name, results in data["tool_results"].items():
                tool_elem = SubElement(tools_elem, "tool", name=tool_name)
                for result in results:
                    result_elem = SubElement(tool_elem, "result")
                    for key, value in result.items():
                        SubElement(result_elem, key).text = str(value)

        rough_string = tostring(root, "utf-8")
        reparsed = minidom.parseString(rough_string)
        with open(filename, "w") as f:
            f.write(reparsed.toprettyxml(indent="  "))
