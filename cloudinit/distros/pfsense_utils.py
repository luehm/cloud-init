# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import lxml.etree as ET

from cloudinit import util

def _element_to_dict(element):
    """
    Recursively converts an ElementTree Element to a Python dictionary.
    """
    # If the element has no children, return its text directly (if available)
    if not list(element):  # No child elements
        return element.text.strip() if element.text and element.text.strip() else None

    # If the element has children, construct a dictionary
    obj = {}
    # Add attributes of the element (if any)
    obj.update(element.attrib)

    # Process child elements
    for child in element:
        child_obj = _element_to_dict(child)
        if child.tag not in obj:
            obj[child.tag] = child_obj
        else:
            # If multiple children have the same tag, convert to a list
            if not isinstance(obj[child.tag], list):
                obj[child.tag] = [obj[child.tag]]
            obj[child.tag].append(child_obj)

    return obj

def _dict_to_element(tag, data):
    """
    Recursively converts a Python dictionary to an ElementTree Element.
    """
    # Create the root element
    element = ET.Element(tag)

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                # Handle list of elements with the same tag
                for item in value:
                    element.append(_dict_to_element(key, item))
            elif isinstance(value, dict):
                # Handle nested dictionaries
                element.append(_dict_to_element(key, value))
            else:
                subelement = ET.Element(key)
                # Handle attributes or text content
                if value is None :
                    subelement.text = ""
                else:
                    subelement.text = value
                element.append(subelement)
    else:
        # If the data is a simple value, set it as text
        if data is None:
            element.text = ""
        else:
            element.text = str(data)

    return element

def get_config_element(tree_path, fp="/cf/conf/config.xml"):
    """
    For the given xml path in key, get the element
    """

    # Find element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    nodes = root.findall(tree_path)
    if nodes is None:
        return False

    # Convert nodes to dictionaries
    if len(nodes) == 1:
        # Return a single dictionary if only one element matches
        return _element_to_dict(nodes[0])
    else:
        # Return a list of dictionaries if multiple elements match
        return [_element_to_dict(node) for node in nodes]

def append_config_element(tree_path, element, fp="/cf/conf/config.xml"):
    """
    For the given xml path, create an element with the specified properties.
    """

    # Find parent element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    n = root.find(tree_path.split("/")[-2])
    if n is None:
        raise ValueError("No such key: %s" % tree_path)

    # Append element to parent node
    n.append(_dict_to_element(tree_path.split("/")[-1], element))

    # Write changes to file
    tree.write(fp, pretty_print=True)

def replace_config_element(tree_path, key, value, node, fp="/cf/conf/config.xml"):
    """
    For the given xml path, replace the value of the specified element
    """

    # Find existing element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    nodes = root.findall(tree_path)
    old_node = None
    for n in nodes:
        if n.find(key).text == value:
            old_node = n
            break
    if old_node is None:
        raise ValueError("No such key: %s" % tree_path)

    # Swap old element with new element
    parent = old_node.getparent()
    parent.remove(old_node)
    parent.append(_dict_to_element(tree_path.split("/")[-1], node))

    # Write changes to file
    tree.write(fp, pretty_print=True)

def get_config_value(tree_path, fp="/cf/conf/config.xml"):
    """
    For the given xml path in key, get the value
    """

    # Find element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    node = root.find(tree_path)
    if node is None:
        return False

    return node.text

def set_config_value(tree_path, value, fp="/cf/conf/config.xml"):
    """
    For the givem xml path, set the value of the specified element
    """

    # Find parent element in document
    xml_parser = ET.XMLParser(remove_blank_text=True)
    tree = ET.parse(fp, xml_parser)
    root = tree.getroot()
    n = root.find(tree_path)
    if n is None:
        raise ValueError("No such key: %s" % tree_path)

    # Set element value
    n.text = value

    # Write changes to file
    tree.write(fp, pretty_print=True)
