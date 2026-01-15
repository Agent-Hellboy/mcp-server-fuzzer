"""XML formatter implementation."""

from __future__ import annotations

from typing import Any

from .common import extract_tool_runs, normalize_report_data


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

        def add_fields(parent: Element, mapping: dict[str, Any]):
            for key, value in mapping.items():
                field = SubElement(parent, "field", name=str(key))
                field.text = str(value)

        if "metadata" in data:
            metadata_elem = SubElement(root, "metadata")
            add_fields(metadata_elem, data["metadata"])

        if "tool_results" in data:
            tools_elem = SubElement(root, "tool-results")
            for tool_name, results in data["tool_results"].items():
                runs, _ = extract_tool_runs(results)
                tool_elem = SubElement(tools_elem, "tool", name=tool_name)
                for result in runs:
                    result_elem = SubElement(tool_elem, "result")
                    add_fields(result_elem, result)

        rough_string = tostring(root, "utf-8")
        reparsed = minidom.parseString(rough_string)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(reparsed.toprettyxml(indent="  "))
