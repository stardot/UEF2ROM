__all__ = ["diskutils", "joystick", "makedfs", "UEFfile"]

def format_data(data):

    s = ""
    i = 0
    
    while i < len(data):
        s += ".byte " + ",".join(map(lambda x: "$%02x" % ord(x), data[i:i+24]))
        i += 24
    
    return s
