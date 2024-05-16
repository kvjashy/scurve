#!/usr/bin/env python
import os
import string
import scurve
from scurve import progress, utils, draw
from PIL import Image, ImageDraw
import numpy as np
import pandas as pd

class _Color:
    def __init__(self, data, block):
        self.data, self.block = data, block
        s = list(set(data))
        s.sort()
        self.symbol_map = {v: i for (i, v) in enumerate(s)}

    def __len__(self):
        return len(self.data)

    def point(self, x):
        if self.block and (self.block[0] <= x < self.block[1]):
            return self.block[2]
        else:
            return self.getPoint(x)

class ColorGradient(_Color):
    def getPoint(self, x):
        c = ord(self.data[x]) / 255.0
        return [int(255 * c), int(255 * c), int(255 * c)]

class ColorHilbert(_Color):
    def __init__(self, data, block):
        _Color.__init__(self, data, block)
        self.csource = scurve.fromSize("hilbert", 3, 256**3)
        self.step = len(self.csource) / float(len(self.symbol_map))

    def getPoint(self, x):
        c = self.symbol_map[self.data[x]]
        return self.csource.point(int(c * self.step))

class ColorClass(_Color):
    def getPoint(self, x):
        c = self.data[x]
        if c == 0:
            return [0, 0, 0]
        elif c == 255:
            return [255, 255, 255]
        elif chr(c) in string.printable:
            return [55, 126, 184]
        return [228, 26, 28]

class ColorEntropy(_Color):
    def getPoint(self, x):
        e = utils.entropy(self.data, 32, x, len(self.symbol_map))
        def curve(v):
            f = (4 * v - 4 * v**2)**4
            f = max(f, 0)
            return f
        r = curve(e - 0.5) if e > 0.5 else 0
        b = e**2
        return [int(255 * r), 0, int(255 * b)]

def drawmap_unrolled(map, size, csource, name, prog):
    prog.set_target((size**2) * 4)
    map = scurve.fromSize(map, 2, size**2)
    c = Image.new("RGB", (size, size * 4))
    cd = ImageDraw.Draw(c)
    step = len(csource) / float(len(map) * 4)

    sofar = 0
    for quad in range(4):
        for i, p in enumerate(map):
            off = i + (quad * size**2)
            color = csource.point(int(off * step))
            x, y = tuple(p)
            cd.point((x, y + (size * quad)), fill=tuple(color))
            if not sofar % 100:
                prog.tick(sofar)
            sofar += 1
    c.save(name)
    return np.array(c).flatten()

def drawmap_square(map, size, csource, name, prog):
    prog.set_target((size**2))
    map = scurve.fromSize(map, 2, size**2)
    c = Image.new("RGB", map.dimensions())
    cd = ImageDraw.Draw(c)
    step = len(csource) / float(len(map))
    for i, p in enumerate(map):
        color = csource.point(int(i * step))
        cd.point(tuple(p), fill=tuple(color))
        if not i % 100:
            prog.tick(i)
    c.save(name)
    return np.array(c).flatten()

def process_file(file_path, output_dir, options):
    with open(file_path, 'rb') as f:
        d = f.read()

    base = os.path.basename(file_path)
    if "." in base:
        base, _ = base.rsplit(".", 1)
    dst = os.path.join(output_dir, base + options.suffix + ".png")
    
    if os.path.exists(dst) and not options.overwrite:
        print(f"Refusing to over-write '{dst}'. Specify explicitly if you really want to do this.")
        return

    block = None
    if options.block:
        parts = options.block.split(":")
        if len(parts) not in [2, 3]:
            raise ValueError("Invalid block specification.")
        s, e = int(parts[0], 16), int(parts[1], 16)
        if len(parts) == 3:
            c = draw.parseColor(parts[2])
        else:
            c = [255, 0, 0]
        block = (s, e, c)

    if options.color == "class":
        csource = ColorClass(d, block)
    elif options.color == "hilbert":
        csource = ColorHilbert(d, block)
    elif options.color == "gradient":
        csource = ColorGradient(d, block)
    else:
        csource = ColorEntropy(d, block)

    prog = progress.Progress(None) if not options.quiet else progress.Dummy()

    if options.type == "unrolled":
        flattened_vector = drawmap_unrolled(options.map, options.size, csource, dst, prog)
    elif options.type == "square":
        flattened_vector = drawmap_square(options.map, options.size, csource, dst, prog)

    prog.clear()

    filename_parts = os.path.basename(file_path).split('_')
    hash_value = '_'.join(filename_parts[:-2])
    malware_status = filename_parts[-1].split('.')[0]

    data_dict = {
        "hash": hash_value,
        **{f"pix_{i}": pixel for i, pixel in enumerate(flattened_vector)},
        "malware": int(malware_status)
    }

    df_path = 'output_vectors2.csv'
    if os.path.exists(df_path):
        results_df = pd.read_csv(df_path)
    else:
        results_df = pd.DataFrame()

    new_row = pd.DataFrame([data_dict])

    results_df = pd.concat([results_df, new_row], ignore_index=True)

    results_df.to_csv(df_path, index=False)

def main():
    from optparse import OptionParser
    parser = OptionParser(
        usage="%prog [options] infile [output]",
        version="%prog 0.1",
    )
    parser.add_option(
        "-b", "--block", action="store",
        dest="block", default=None,
        help="Mark a block of data with a specified color. Format: hexstartaddr:hexendaddr[:hexcolor]"
    )
    parser.add_option(
        "-c", "--color", action="store",
        type="choice", dest="color", default="class",
        choices=["class", "hilbert", "entropy", "gradient"],
        help="Color map."
    )
    parser.add_option(
        "-m", "--map", action="store",
        type="choice", dest="map", default="hilbert",
        choices=sorted(scurve.curveMap.keys()),
        help="Pixel layout map. Can be any supported curve."
    )
    parser.add_option(
        "-n", "--namesuffix", action="store",
        type="str", dest="suffix", default="",
        help="Suffix for generated file names. Ignored if destination is specified."
    )
    parser.add_option(
        "-s", "--size", action="store",
        type="int", dest="size", default=256,
        help="Image width in pixels."
    )
    parser.add_option(
        "-t", "--type", type="choice",
        dest="type", default="unrolled",
        choices=["unrolled", "square"],
        help="Image aspect ratio - square (1x1) or unrolled (1x4)"
    )
    parser.add_option(
        "-q", "--quiet", action="store_true",
        dest="quiet", default=False
    )
    parser.add_option(
        "-w", "--overwrite", action="store_true",
        dest="overwrite", default=False,
        help="Allow overwriting existing files."
    )
    options, _ = parser.parse_args()

    input_dir = '/home/kev/Documents/MalwareAnalysisProject/test_binary_files'  # Specify your input directory containing the files to process
    output_dir = 'output_images'  # Specify your output directory
    os.makedirs(output_dir, exist_ok=True)

    for file_name in os.listdir(input_dir):
        file_path = os.path.join(input_dir, file_name)
        if os.path.isfile(file_path):
            process_file(file_path, output_dir, options)

if __name__ == "__main__":
    main()
