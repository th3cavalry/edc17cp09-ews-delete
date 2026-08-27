#!/usr/bin/env python3
"""
EDC17CP09 XDF Generator v2 - Proper Classification
Based on detailed axis analysis and EDC17 structure knowledge
"""

import json
import struct
import xml.etree.ElementTree as ET
from xml.dom import minidom

# Map classification based on axis analysis
MAP_CLASSIFICATIONS = {
    0: {"name": "Engine Speed Normalization", "category": "Engine Management", "x_label": "Index", "y_label": "Index", "z_label": "Factor", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    1: {"name": "Load Calculation Table 1", "category": "Engine Management", "x_label": "Parameter 1", "y_label": "Parameter 2", "z_label": "Load Value", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    2: {"name": "Load Calculation Table 2", "category": "Engine Management", "x_label": "Parameter 1", "y_label": "Parameter 2", "z_label": "Load Value", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    3: {"name": "Temperature Compensation (High Temp)", "category": "Temperature Management", "x_label": "Temperature [°C ×0.1]", "y_label": "Temperature [°C ×0.1]", "z_label": "Factor", "x_factor": 0.1, "y_factor": 0.1, "z_factor": 1.0},
    4: {"name": "Sensor Calibration", "category": "Engine Management", "x_label": "Raw Value", "y_label": "Raw Value", "z_label": "Calibrated", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    5: {"name": "Start of Injection - Main (SOI)", "category": "Injection System", "x_label": "Engine Speed [RPM]", "y_label": "Fuel Quantity [mm³]", "z_label": "Timing [°BTDC]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    6: {"name": "Driver Wish - Pedal to Torque Request", "category": "Torque Structure", "x_label": "Pedal Position [%]", "y_label": "Engine Speed [RPM]", "z_label": "Torque Request [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    7: {"name": "Injection Duration - Main Injection", "category": "Injection System", "x_label": "Engine Speed [RPM]", "y_label": "Fuel Quantity [mm³]", "z_label": "Duration [µs]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    8: {"name": "Fuel Quantity Limiter (High RPM)", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Max Fuel [mg]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    9: {"name": "Fuel Quantity Limiter (Extended)", "category": "Torque Structure", "x_label": "Parameter", "y_label": "Engine Speed [RPM]", "z_label": "Max Fuel [mg]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    10: {"name": "Torque Limiter - Mode 1", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    11: {"name": "Torque Limiter - Mode 1 (Detailed)", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    12: {"name": "Torque Limiter - Mode 2", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    13: {"name": "Torque Limiter - Mode 2 (Detailed)", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    14: {"name": "Torque Limiter - Mode 3", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    15: {"name": "Torque Limiter - Mode 3 (Detailed)", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    16: {"name": "Torque Limiter - Mode 4", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    17: {"name": "Torque Limiter - Mode 4 (Detailed)", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    18: {"name": "Rail Pressure Request", "category": "Rail System", "x_label": "Engine Speed [RPM]", "y_label": "Fuel Quantity [mm³]", "z_label": "Pressure [bar]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    19: {"name": "Torque Limiter - Mode 5", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    20: {"name": "Torque Limiter - Mode 5 (Detailed)", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    21: {"name": "Torque Limiter - Mode 6", "category": "Torque Structure", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    22: {"name": "Torque Limiter - Mode 6 (Narrow)", "category": "Torque Structure", "x_label": "Parameter", "y_label": "Engine Speed [RPM]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    23: {"name": "Temperature Compensation - Low Range", "category": "Temperature Management", "x_label": "Temperature [°C]", "y_label": "Engine Speed [RPM]", "z_label": "Correction Factor", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 0.001},
    24: {"name": "Temperature Compensation - Mid Range", "category": "Temperature Management", "x_label": "Temperature [°C]", "y_label": "Parameter", "z_label": "Correction Factor", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 0.001},
    25: {"name": "Volumetric Efficiency Map", "category": "Boost & Airpath", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Efficiency [%]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 0.1},
    26: {"name": "FMTC - Fuel to Torque Conversion 1", "category": "Torque Structure", "x_label": "Fuel Quantity [mm³]", "y_label": "Engine Speed [RPM]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    27: {"name": "Injection Duration - Rail Pressure Dependent 1", "category": "Injection System", "x_label": "Rail Pressure [bar]", "y_label": "Fuel Quantity [mm³]", "z_label": "Duration [µs]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    28: {"name": "FMTC - Fuel to Torque Conversion 2", "category": "Torque Structure", "x_label": "Fuel Quantity [mm³]", "y_label": "Engine Speed [RPM]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    29: {"name": "Injection Duration - Rail Pressure Dependent 2", "category": "Injection System", "x_label": "Rail Pressure [bar]", "y_label": "Fuel Quantity [mm³]", "z_label": "Duration [µs]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    30: {"name": "FMTC - Fuel to Torque Conversion 3", "category": "Torque Structure", "x_label": "Fuel Quantity [mm³]", "y_label": "Engine Speed [RPM]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    31: {"name": "Idle Speed Control", "category": "Idle Control", "x_label": "Fuel Quantity [mm³]", "y_label": "Engine Speed [RPM]", "z_label": "Target RPM", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    32: {"name": "Sensor Linearization", "category": "Engine Management", "x_label": "Raw Input", "y_label": "Raw Input", "z_label": "Linearized Output", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    33: {"name": "Driver Wish - Torque Request (Large)", "category": "Torque Structure", "x_label": "Pedal Position [%]", "y_label": "Engine Speed [RPM]", "z_label": "Torque [Nm]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    34: {"name": "Driver Wish - Fuel Request (Large)", "category": "Torque Structure", "x_label": "Pedal Position [%]", "y_label": "Engine Speed [RPM]", "z_label": "Fuel [mg]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    35: {"name": "Rail Pressure Request - Low Range", "category": "Rail System", "x_label": "Rail Pressure [bar]", "y_label": "Engine Speed [RPM]", "z_label": "Target Pressure [bar]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    36: {"name": "Rail Pressure Limiter", "category": "Rail System", "x_label": "Rail Pressure [bar]", "y_label": "Engine Speed [RPM]", "z_label": "Max Pressure [bar]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    37: {"name": "Temperature Compensation - Narrow Range", "category": "Temperature Management", "x_label": "Temperature [°C ×0.1]", "y_label": "Temperature [°C ×0.1]", "z_label": "Factor", "x_factor": 0.1, "y_factor": 0.1, "z_factor": 1.0},
    38: {"name": "Boost Pressure Request", "category": "Boost & Airpath", "x_label": "Engine Speed [RPM]", "y_label": "Load [%]", "z_label": "Boost [mbar]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
    39: {"name": "Injection Duration - Extended Range", "category": "Injection System", "x_label": "Engine Speed [RPM]", "y_label": "Fuel Quantity [mm³]", "z_label": "Duration [µs]", "x_factor": 1.0, "y_factor": 1.0, "z_factor": 1.0},
}

def generate_xdf():
    """Generate XDF with proper classifications"""
    
    # Load maps data
    with open('/home/brandon/Documents/EDC17CP09/maps_decoded.json', 'r') as f:
        maps = json.load(f)
    
    with open('/home/brandon/Documents/EDC17CP09/mpc_full.bin', 'rb') as f:
        data = f.read()
    
    # Create XDF root
    root = ET.Element('XDF')
    root.set('version', '1.0')
    
    # Add header
    header = ET.SubElement(root, 'XDFHEADER')
    ET.SubElement(header, 'XDFVERSION').text = '1.0'
    ET.SubElement(header, 'XDFNAME').text = 'EDC17CP09_M57_0281017487'
    ET.SubElement(header, 'XDFDESC').text = 'BMW EDC17CP09 M57 3.0D - US Spec X5 35d (E70)'
    ET.SubElement(header, 'XDFBIN').text = 'mpc_full.bin'
    ET.SubElement(header, 'XDFSIZE').text = str(len(data))
    
    # Generate tables
    for i, m in enumerate(maps):
        if i not in MAP_CLASSIFICATIONS:
            continue
            
        cls = MAP_CLASSIFICATIONS[i]
        
        table = ET.SubElement(root, 'TABLE')
        table.set('uniqueid', f'0x{i:04X}')
        table.set('name', cls['name'])
        table.set('category', cls['category'])
        table.set('type', '3D')
        
        # Address and dimensions
        ET.SubElement(table, 'EMBEDDEDDATA').set('mmedaddress', f'0x{m["off"]:06X}')
        ET.SubElement(table, 'EMBEDDEDDATA').set('mmedrowcount', str(m['rows']))
        ET.SubElement(table, 'EMBEDDEDDATA').set('mmedcolcount', str(m['cols']))
        ET.SubElement(table, 'EMBEDDEDDATA').set('mmedelementsizebytes', '2')
        
        # Labels
        ET.SubElement(table, 'LABEL').set('index', '1')
        ET.SubElement(table, 'LABEL').set('value', cls['x_label'])
        ET.SubElement(table, 'LABEL').set('index', '2')
        ET.SubElement(table, 'LABEL').set('value', cls['y_label'])
        ET.SubElement(table, 'LABEL').set('index', '3')
        ET.SubElement(table, 'LABEL').set('value', cls['z_label'])
        
        # Math (scaling factors)
        math_x = ET.SubElement(table, 'MATH')
        math_x.set('equation', f'X*{cls["x_factor"]}')
        math_x.set('var', 'X')
        
        math_y = ET.SubElement(table, 'MATH')
        math_y.set('equation', f'X*{cls["y_factor"]}')
        math_y.set('var', 'Y')
        
        math_z = ET.SubElement(table, 'MATH')
        math_z.set('equation', f'X*{cls["z_factor"]}')
        math_z.set('var', 'Z')
    
    # Write XDF
    xml_str = ET.tostring(root, encoding='unicode')
    pretty_xml = minidom.parseString(xml_str).toprettyxml(indent='  ')
    
    with open('/home/brandon/Documents/EDC17CP09/EDC17CP09_M57_0281017487_v2.xdf', 'w') as f:
        f.write(pretty_xml)
    
    print(f"Generated XDF with {len(MAP_CLASSIFICATIONS)} classified maps")
    print("Output: EDC17CP09_M57_0281017487_v2.xdf")

if __name__ == '__main__':
    generate_xdf()
