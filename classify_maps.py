#!/usr/bin/env python3
"""
Classify and label all 40 maps based on EDC17 structure knowledge
"""
import json
import struct

def analyze_map(m, data):
    """Analyze a single map's structure and classify it"""
    offset = m['off']
    rows = m['rows']
    cols = m['cols']
    
    # Read axes
    x_off = offset - (cols * 2)
    y_off = x_off - (rows * 2)
    
    x_vals = [struct.unpack('<H', data[x_off + j*2:x_off + j*2 + 2])[0] for j in range(cols)]
    y_vals = [struct.unpack('<H', data[y_off + j*2:y_off + j*2 + 2])[0] for j in range(rows)]
    z_vals = [struct.unpack('<H', data[offset + r*cols*2 + c*2:offset + r*cols*2 + c*2 + 2])[0] 
              for r in range(rows) for c in range(cols)]
    
    x_min, x_max = min(x_vals), max(x_vals)
    y_min, y_max = min(y_vals), max(y_vals)
    z_min, z_max = min(z_vals), max(z_vals)
    
    return {
        'offset': offset,
        'rows': rows,
        'cols': cols,
        'x_min': x_min, 'x_max': x_max,
        'y_min': y_min, 'y_max': y_max,
        'z_min': z_min, 'z_max': z_max,
        'x_vals': x_vals,
        'y_vals': y_vals
    }

def classify_map(info):
    """Classify map based on axis ranges and structure"""
    x_min, x_max = info['x_min'], info['x_max']
    y_min, y_max = info['y_min'], info['y_max']
    z_min, z_max = info['z_min'], info['z_max']
    rows, cols = info['rows'], info['cols']
    
    # Injection duration/timing maps
    if x_max == 7000 and y_max == 2400 and z_max < 500:
        return {
            'category': 'Injection System',
            'name': 'Injection Duration - Main Injection',
            'x_label': 'Engine Speed [RPM]',
            'y_label': 'Fuel Quantity [mm³]',
            'z_label': 'Duration [µs]',
            'x_factor': 1.0, 'y_factor': 1.0, 'z_factor': 1.0
        }
    
    # Rail pressure maps (high values on both axes)
    if x_min > 5000 and y_min > 5000 and x_max < 10000:
        return {
            'category': 'Rail System',
            'name': 'Rail Pressure Request',
            'x_label': 'Engine Speed [RPM]',
            'y_label': 'Fuel Quantity [mm³]',
            'z_label': 'Pressure [bar]',
            'x_factor': 1.0, 'y_factor': 1.0, 'z_factor': 1.0
        }
    
    # Torque limiter / fuel quantity maps
    if x_max == 7500 and y_max == 10000 and z_max < 2000:
        return {
            'category': 'Torque Structure',
            'name': 'Torque Limiter',
            'x_label': 'Engine Speed [RPM]',
            'y_label': 'Load [%]',
            'z_label': 'Torque [Nm]',
            'x_factor': 1.0, 'y_factor': 1.0, 'z_factor': 1.0
        }
    
    # Temperature maps (very high values)
    if x_max > 25000 or y_max > 25000:
        return {
            'category': 'Temperature Management',
            'name': 'Temperature Compensation',
            'x_label': 'Temperature [°C]',
            'y_label': 'Temperature [°C]',
            'z_label': 'Factor [-]',
            'x_factor': 0.1, 'y_factor': 0.1, 'z_factor': 0.001
        }
    
    # Generic classification
    return {
        'category': 'Engine Management',
        'name': f'Map @ 0x{info["offset"]:06X}',
        'x_label': 'X-Axis',
        'y_label': 'Y-Axis',
        'z_label': 'Z-Value',
        'x_factor': 1.0, 'y_factor': 1.0, 'z_factor': 1.0
    }

def main():
    # Load data
    with open('/home/brandon/Documents/EDC17CP09/maps_decoded.json', 'r') as f:
        maps = json.load(f)
    
    with open('/home/brandon/Documents/EDC17CP09/mpc_full.bin', 'rb') as f:
        data = f.read()
    
    # Classify all maps
    classified = []
    for i, m in enumerate(maps):
        info = analyze_map(m, data)
        classification = classify_map(info)
        classified.append({
            'index': i,
            **info,
            **classification
        })
    
    # Save classification
    with open('/home/brandon/Documents/EDC17CP09/maps_classified.json', 'w') as f:
        json.dump(classified, f, indent=2)
    
    # Print summary
    print(f"Classified {len(classified)} maps\n")
    for c in classified:
        print(f"Map {c['index']:3d} @ 0x{c['offset']:06X} ({c['rows']:2d}x{c['cols']:2d}): "
              f"{c['category']:30s} - {c['name']}")

if __name__ == '__main__':
    main()
