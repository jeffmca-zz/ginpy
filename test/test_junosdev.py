import unittest
import ginpy
from lxml import etree

class Test_JunosDev(unittest.TestCase):
    def setUp(self):
        self.jdev = ginpy.JunosDev("3a-4.appriss.net", "sysjeff")

    def test_name(self):
        self.assertEqual( self.jdev.name, "3a-4.appriss.net")

    def test_get_config(self):
        self.assertIsInstance( self.jdev.xmlconfig, etree._Element)
