COUNTER
=======

Register Listing for COUNTER
----------------------------

+------------------------------------------+-------------------------------------+
| Register                                 | Address                             |
+==========================================+=====================================+
| :ref:`COUNTER_CONTROL <COUNTER_CONTROL>` | :ref:`0xf0000800 <COUNTER_CONTROL>` |
+------------------------------------------+-------------------------------------+
| :ref:`COUNTER_COUNT <COUNTER_COUNT>`     | :ref:`0xf0000804 <COUNTER_COUNT>`   |
+------------------------------------------+-------------------------------------+
| :ref:`COUNTER_RELOAD <COUNTER_RELOAD>`   | :ref:`0xf0000808 <COUNTER_RELOAD>`  |
+------------------------------------------+-------------------------------------+
| :ref:`COUNTER_RESET <COUNTER_RESET>`     | :ref:`0xf000080c <COUNTER_RESET>`   |
+------------------------------------------+-------------------------------------+

COUNTER_CONTROL
^^^^^^^^^^^^^^^

`Address: 0xf0000800 + 0x0 = 0xf0000800`

    控制寄存器: bit0=enable

    .. wavedrom::
        :caption: COUNTER_CONTROL

        {
            "reg": [
                {"name": "control", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


COUNTER_COUNT
^^^^^^^^^^^^^

`Address: 0xf0000800 + 0x4 = 0xf0000804`

    当前计数值

    .. wavedrom::
        :caption: COUNTER_COUNT

        {
            "reg": [
                {"name": "count[31:0]", "bits": 32}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 1 }, "options": {"hspace": 400, "bits": 32, "lanes": 1}
        }


COUNTER_RELOAD
^^^^^^^^^^^^^^

`Address: 0xf0000800 + 0x8 = 0xf0000808`

    重载值

    .. wavedrom::
        :caption: COUNTER_RELOAD

        {
            "reg": [
                {"name": "reload[31:0]", "bits": 32}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 1 }, "options": {"hspace": 400, "bits": 32, "lanes": 1}
        }


COUNTER_RESET
^^^^^^^^^^^^^

`Address: 0xf0000800 + 0xc = 0xf000080c`

    写1触发复位

    .. wavedrom::
        :caption: COUNTER_RESET

        {
            "reg": [
                {"name": "reset", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


