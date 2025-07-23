import os
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import QDir

def initialize_resources():
    """Initialize application resources (icons, images, etc.)"""
    resource_dir = os.path.join(os.path.dirname(__file__), '..', 'assets', 'icons')
    if not os.path.exists(resource_dir):
        os.makedirs(resource_dir)
    
    QDir.addSearchPath('icons', resource_dir)

def get_icon(name):
    """Get QIcon from resources"""
    return QIcon.fromTheme(name, QIcon(f"icons:{name}.png"))

def get_pixmap(name):
    """Get QPixmap from resources"""
    return QPixmap(f"icons:{name}.png")