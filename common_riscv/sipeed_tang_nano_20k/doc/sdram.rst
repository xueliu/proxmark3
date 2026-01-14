SDRAM
=====

Register Listing for SDRAM
--------------------------

+--------------------------------------------------------------------+--------------------------------------------------+
| Register                                                           | Address                                          |
+====================================================================+==================================================+
| :ref:`SDRAM_DFII_CONTROL <SDRAM_DFII_CONTROL>`                     | :ref:`0xf0003000 <SDRAM_DFII_CONTROL>`           |
+--------------------------------------------------------------------+--------------------------------------------------+
| :ref:`SDRAM_DFII_PI0_COMMAND <SDRAM_DFII_PI0_COMMAND>`             | :ref:`0xf0003004 <SDRAM_DFII_PI0_COMMAND>`       |
+--------------------------------------------------------------------+--------------------------------------------------+
| :ref:`SDRAM_DFII_PI0_COMMAND_ISSUE <SDRAM_DFII_PI0_COMMAND_ISSUE>` | :ref:`0xf0003008 <SDRAM_DFII_PI0_COMMAND_ISSUE>` |
+--------------------------------------------------------------------+--------------------------------------------------+
| :ref:`SDRAM_DFII_PI0_ADDRESS <SDRAM_DFII_PI0_ADDRESS>`             | :ref:`0xf000300c <SDRAM_DFII_PI0_ADDRESS>`       |
+--------------------------------------------------------------------+--------------------------------------------------+
| :ref:`SDRAM_DFII_PI0_BADDRESS <SDRAM_DFII_PI0_BADDRESS>`           | :ref:`0xf0003010 <SDRAM_DFII_PI0_BADDRESS>`      |
+--------------------------------------------------------------------+--------------------------------------------------+
| :ref:`SDRAM_DFII_PI0_WRDATA <SDRAM_DFII_PI0_WRDATA>`               | :ref:`0xf0003014 <SDRAM_DFII_PI0_WRDATA>`        |
+--------------------------------------------------------------------+--------------------------------------------------+
| :ref:`SDRAM_DFII_PI0_RDDATA <SDRAM_DFII_PI0_RDDATA>`               | :ref:`0xf0003018 <SDRAM_DFII_PI0_RDDATA>`        |
+--------------------------------------------------------------------+--------------------------------------------------+

SDRAM_DFII_CONTROL
^^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x0 = 0xf0003000`

    Control DFI signals common to all phases

    .. wavedrom::
        :caption: SDRAM_DFII_CONTROL

        {
            "reg": [
                {"name": "sel",  "attr": '1', "bits": 1},
                {"name": "cke",  "bits": 1},
                {"name": "odt",  "bits": 1},
                {"name": "reset_n",  "bits": 1},
                {"bits": 28}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+---------+-------------------------------------------+
| Field | Name    | Description                               |
+=======+=========+===========================================+
| [0]   | SEL     |                                           |
|       |         |                                           |
|       |         | +---------+-----------------------------+ |
|       |         | | Value   | Description                 | |
|       |         | +=========+=============================+ |
|       |         | | ``0b0`` | Software (CPU) control.     | |
|       |         | +---------+-----------------------------+ |
|       |         | | ``0b1`` | Hardware control (default). | |
|       |         | +---------+-----------------------------+ |
+-------+---------+-------------------------------------------+
| [1]   | CKE     | DFI clock enable bus                      |
+-------+---------+-------------------------------------------+
| [2]   | ODT     | DFI on-die termination bus                |
+-------+---------+-------------------------------------------+
| [3]   | RESET_N | DFI clock reset bus                       |
+-------+---------+-------------------------------------------+

SDRAM_DFII_PI0_COMMAND
^^^^^^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x4 = 0xf0003004`

    Control DFI signals on a single phase

    .. wavedrom::
        :caption: SDRAM_DFII_PI0_COMMAND

        {
            "reg": [
                {"name": "cs",  "bits": 1},
                {"name": "we",  "bits": 1},
                {"name": "cas",  "bits": 1},
                {"name": "ras",  "bits": 1},
                {"name": "wren",  "bits": 1},
                {"name": "rden",  "bits": 1},
                {"name": "cs_top",  "bits": 1},
                {"name": "cs_bottom",  "bits": 1},
                {"bits": 24}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+-----------+------------------------------------------+
| Field | Name      | Description                              |
+=======+===========+==========================================+
| [0]   | CS        | DFI chip select bus                      |
+-------+-----------+------------------------------------------+
| [1]   | WE        | DFI write enable bus                     |
+-------+-----------+------------------------------------------+
| [2]   | CAS       | DFI column address strobe bus            |
+-------+-----------+------------------------------------------+
| [3]   | RAS       | DFI row address strobe bus               |
+-------+-----------+------------------------------------------+
| [4]   | WREN      | DFI write data enable bus                |
+-------+-----------+------------------------------------------+
| [5]   | RDEN      | DFI read data enable bus                 |
+-------+-----------+------------------------------------------+
| [6]   | CS_TOP    | DFI chip select bus for top half only    |
+-------+-----------+------------------------------------------+
| [7]   | CS_BOTTOM | DFI chip select bus for bottom half only |
+-------+-----------+------------------------------------------+

SDRAM_DFII_PI0_COMMAND_ISSUE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x8 = 0xf0003008`


    .. wavedrom::
        :caption: SDRAM_DFII_PI0_COMMAND_ISSUE

        {
            "reg": [
                {"name": "dfii_pi0_command_issue", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


SDRAM_DFII_PI0_ADDRESS
^^^^^^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0xc = 0xf000300c`

    DFI address bus

    .. wavedrom::
        :caption: SDRAM_DFII_PI0_ADDRESS

        {
            "reg": [
                {"name": "dfii_pi0_address[10:0]", "bits": 11},
                {"bits": 21},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 1 }, "options": {"hspace": 400, "bits": 32, "lanes": 1}
        }


SDRAM_DFII_PI0_BADDRESS
^^^^^^^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x10 = 0xf0003010`

    DFI bank address bus

    .. wavedrom::
        :caption: SDRAM_DFII_PI0_BADDRESS

        {
            "reg": [
                {"name": "dfii_pi0_baddress[1:0]", "bits": 2},
                {"bits": 30},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


SDRAM_DFII_PI0_WRDATA
^^^^^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x14 = 0xf0003014`

    DFI write data bus

    .. wavedrom::
        :caption: SDRAM_DFII_PI0_WRDATA

        {
            "reg": [
                {"name": "dfii_pi0_wrdata[31:0]", "bits": 32}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 1 }, "options": {"hspace": 400, "bits": 32, "lanes": 1}
        }


SDRAM_DFII_PI0_RDDATA
^^^^^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x18 = 0xf0003018`

    DFI read data bus

    .. wavedrom::
        :caption: SDRAM_DFII_PI0_RDDATA

        {
            "reg": [
                {"name": "dfii_pi0_rddata[31:0]", "bits": 32}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 1 }, "options": {"hspace": 400, "bits": 32, "lanes": 1}
        }


