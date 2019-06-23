#!/usr/bin/env python3
"""Module to generate random endpoint value"""
import random

def generate_GUID():
    """Generate random GUID"""
    random_GUI = (format((random.randint(0x10000000,0xFFFFFFFF)), 'x')
        + '-' + format((random.randint(0x1000,0xFFFF)), 'x')
        + '-' + format((random.randint(0x1000,0xFFFF)), 'x')
        + '-' + format((random.randint(0x1000,0xFFFF)), 'x')
        + '-' + format((random.randint(0x100000000000,0xFFFFFFFFFFFF)), 'x')
                  )
    return random_GUI


def generate_hostname():
    """Generate hostname"""
    hostname = 'harry-' + format((random.randint(0x10000000,0xFFFFFFFF)), 'x')
    return hostname


def generate_MAC():
    """Generate MAC Address"""
    MAC = format((random.randint(0x100000000000,0xFFFFFFFFFFFF)), 'x')
    return MAC
