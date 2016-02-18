# -*- coding: utf-8 -*-

__author__ = 'Oscar Martinez'
__email__ = 'omtinez@gmail.com'
__version__ = '0.2.3'
__all__ = ['BottleShip', 'data_encode', 'data_decode', 'data_is_encoded']

from bottle import *
from .bottleship import BottleShip, data_encode, data_decode, data_is_encoded
