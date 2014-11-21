#!/usr/bin/env python

# Usage: ./docgen.py ../modules/net.c

import argparse
import subprocess
import re
import sys

parser = argparse.ArgumentParser(description='Generate API docs')
parser.add_argument('--no-comments', default=True, dest='comments', action='store_false',
                    help='render also uncommented declarations')
parser.add_argument('-o', dest='output',
                    help='output file, defaults to stdout')
parser.add_argument('module', help='c file')

args = None

class Decl(object):
    def __init__(self, pos):
        self.source = ""
        self.comment = ""
        self.line, self.offset = map(int, pos.split(','))

    def is_public(self):
        if args.comments:
            return len(self.comment) > 0
        else:
            return True

class FuncDecl(Decl):
    def __init__(self, pos, static, name):
        super(FuncDecl, self).__init__(pos)
        self.static, self.name = static, name

    def __repr__(self):
        return 'Func(%s%s, "%s")' % ('%s, ' % self.static if self.static else "", self.name, self.comment)

    def is_public(self):
        return super(FuncDecl, self).is_public() and self.static == None

class MacroDecl(Decl):
    def __init__(self, pos, name):
        super(MacroDecl, self).__init__(pos)
        self.name = name

    def __repr__(self):
        return 'Macro(%s, "%s")' % (self.name, self.comment)

class StructDecl(Decl):
    def __init__(self, pos, name):
        super(StructDecl, self).__init__(pos)
        self.name = name

    def __repr__(self):
        return 'Struct(%s, "%s")' % (self.name, self.comment)

class InlineDoc(Decl):
    def __init__(self, pos, comment):
        super(InlineDoc, self).__init__(pos)
        self.comment = comment

    def __repr__(self):
        return 'Inline("%s")' % (self.comment)

def parse_tag(src, pos):
    if src.endswith('('):
        return parse_function(src, pos)
    elif src.startswith("#define"):
        return parse_define(src, pos)
    elif src.startswith("struct"):
        return parse_struct(src, pos)

def parse_function(src, pos):
    m = re.match(r"(NS_INTERNAL|static)?.*?(\w*)\(", src)
    if not m:
        print >>sys.stderr, "cannot parse function decl", src
        return None
    return FuncDecl(pos, *m.groups())

def parse_define(src, pos):
    m = re.match(r"#define (\w*)", src)
    if not m:
        print >>sys.stderr, "cannot parse macro", src
        return None
    return MacroDecl(pos, *m.groups())

def parse_struct(src, pos):
    m = re.match(r"struct (\w*)", src)
    if not m:
        print >>sys.stderr, "cannot parse struct", src
        return None
    return StructDecl(pos, *m.groups())

def parse_tags(tags):
    decls = dict()

    it = iter(tags.split('\n'))
    next(it)
    next(it)
    for l in it:
        if not l:
            continue
        src, pos = l.split(chr(0x7f), 2)
        # etags handles functions returning pointers differently
        # when the * appears before the function name with no whitespace.
        pos = pos.split(chr(0x1), 1)[-1]

        decl = parse_tag(src, pos)
        if decl:
            decls[decl.name] = decl
    return decls

def gen_file(path):
    cmd = 'etags -o - --declarations %s' % (path, )
    tags = subprocess.check_output(cmd, shell=True)
    defs = parse_tags(tags)

    src = open('%s' % (path,)).read()
    for decl in defs.values():
        comment_close = src[:decl.offset].rfind('*/')
        comment_open = src[:comment_close].rfind('/*')+2
        if comment_close != (decl.offset - 3):
            continue
        decl.comment = multiline_cleanup(src[comment_open:comment_close])

        # TODO(mkm) this smells, perhaps needs to be made more robust
        # TODO(lsm): move source extraction to type-specific constructor
        if isinstance(decl, FuncDecl):
            end_decl = src[decl.offset:].find('{')
            decl.source = src[decl.offset:decl.offset + end_decl - 1] + ';'
        elif isinstance(decl, StructDecl):
            pos = src[decl.offset:].find('\n}')
            decl.source = src[decl.offset:decl.offset + pos + 3]

    return defs

def gen_module(module):
    c_file = module
    h_file = re.sub(r'\.c$', '.h', module)

    defs = gen_file(h_file)     # Structures/macros are in h_file
    c_defs = gen_file(c_file)   # Functions are in c_file

    # Definitions from .c file override .h file definitions
    defs.update(c_defs)

    res = []
    for k, v in sorted(defs.items(), key=lambda x: x[1].offset):
        if v.is_public():
            res.append(v)
    return res

def extract_inline_doc(module, decls):
    comment = ""
    src = open(module).read()
    first_include = src.find("#include")
    last_comment_close = src[:first_include].rfind("*/")
    last_comment_open = src[:last_comment_close].rfind("/*")
    comment = multiline_cleanup(src[last_comment_open+2:last_comment_close])
    if "All rights reserved" in comment or "Copyright" in comment:
        comment = ""
    decls.insert(0, InlineDoc("1,1", comment))

def multiline_cleanup(comment):
    return ('\n'.join(re.sub(r'^(\* |\*$)', '', l.strip()) for l in comment.split('\n'))).strip()

def render_collection(out, collection, title):
    print >>out, "=== %s" % (title, )
    for decl in collection:
        if decl.comment and 'do_not_export_to_docs' in decl.comment:
            continue
        print >>out, '==== %s\n' % (decl.name, )
        if decl.source:
            print >>out, '[source,c]'
            print >>out, '----'
            print >>out, decl.source
            print >>out, '----'
        print >>out, decl.comment, '\n'

def render(out, mod):
    # TODO(mkm) support multiple inline docs an place them
    # according to their source position.
    inline_docs = [m for m in mod if isinstance(m, InlineDoc) and m.comment]
    for i in inline_docs:
        print >>out, i.comment, '\n'

    funcs = [m for m in mod if isinstance(m, FuncDecl)]
    structs = [m for m in mod if isinstance(m, StructDecl)]

    render_collection(out, structs, 'Structures')
    render_collection(out, funcs, 'Functions')

def main():
    global args
    args = parser.parse_args()

    mod = gen_module(args.module)
    extract_inline_doc(args.module, mod)
    out = sys.stdout if args.output is None else open(args.output, 'w')
    render(out, mod)

if __name__ == '__main__':
    main()
