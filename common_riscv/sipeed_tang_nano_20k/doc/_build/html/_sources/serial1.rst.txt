SERIAL1
=======

Register Listing for SERIAL1
----------------------------

+------------------------------------------------+----------------------------------------+
| Register                                       | Address                                |
+================================================+========================================+
| :ref:`SERIAL1_RXTX <SERIAL1_RXTX>`             | :ref:`0xf0003800 <SERIAL1_RXTX>`       |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL1_TXFULL <SERIAL1_TXFULL>`         | :ref:`0xf0003804 <SERIAL1_TXFULL>`     |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL1_RXEMPTY <SERIAL1_RXEMPTY>`       | :ref:`0xf0003808 <SERIAL1_RXEMPTY>`    |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL1_EV_STATUS <SERIAL1_EV_STATUS>`   | :ref:`0xf000380c <SERIAL1_EV_STATUS>`  |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL1_EV_PENDING <SERIAL1_EV_PENDING>` | :ref:`0xf0003810 <SERIAL1_EV_PENDING>` |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL1_EV_ENABLE <SERIAL1_EV_ENABLE>`   | :ref:`0xf0003814 <SERIAL1_EV_ENABLE>`  |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL1_TXEMPTY <SERIAL1_TXEMPTY>`       | :ref:`0xf0003818 <SERIAL1_TXEMPTY>`    |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL1_RXFULL <SERIAL1_RXFULL>`         | :ref:`0xf000381c <SERIAL1_RXFULL>`     |
+------------------------------------------------+----------------------------------------+

SERIAL1_RXTX
^^^^^^^^^^^^

`Address: 0xf0003800 + 0x0 = 0xf0003800`


    .. wavedrom::
        :caption: SERIAL1_RXTX

        {
            "reg": [
                {"name": "rxtx[7:0]", "bits": 8},
                {"bits": 24},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 1 }, "options": {"hspace": 400, "bits": 32, "lanes": 1}
        }


SERIAL1_TXFULL
^^^^^^^^^^^^^^

`Address: 0xf0003800 + 0x4 = 0xf0003804`

    TX FIFO Full.

    .. wavedrom::
        :caption: SERIAL1_TXFULL

        {
            "reg": [
                {"name": "txfull", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


SERIAL1_RXEMPTY
^^^^^^^^^^^^^^^

`Address: 0xf0003800 + 0x8 = 0xf0003808`

    RX FIFO Empty.

    .. wavedrom::
        :caption: SERIAL1_RXEMPTY

        {
            "reg": [
                {"name": "rxempty", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


SERIAL1_EV_STATUS
^^^^^^^^^^^^^^^^^

`Address: 0xf0003800 + 0xc = 0xf000380c`

    This register contains the current raw level of the rx event trigger.  Writes to
    this register have no effect.

    .. wavedrom::
        :caption: SERIAL1_EV_STATUS

        {
            "reg": [
                {"name": "tx",  "bits": 1},
                {"name": "rx",  "bits": 1},
                {"bits": 30}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+------+---------------------------+
| Field | Name | Description               |
+=======+======+===========================+
| [0]   | TX   | Level of the ``tx`` event |
+-------+------+---------------------------+
| [1]   | RX   | Level of the ``rx`` event |
+-------+------+---------------------------+

SERIAL1_EV_PENDING
^^^^^^^^^^^^^^^^^^

`Address: 0xf0003800 + 0x10 = 0xf0003810`

    When a  rx event occurs, the corresponding bit will be set in this register.  To
    clear the Event, set the corresponding bit in this register.

    .. wavedrom::
        :caption: SERIAL1_EV_PENDING

        {
            "reg": [
                {"name": "tx",  "bits": 1},
                {"name": "rx",  "bits": 1},
                {"bits": 30}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+------+---------------------------------------------------------------------------------+
| Field | Name | Description                                                                     |
+=======+======+=================================================================================+
| [0]   | TX   | `1` if a `tx` event occurred. This Event is **level triggered** when the signal |
|       |      | is **high**.                                                                    |
+-------+------+---------------------------------------------------------------------------------+
| [1]   | RX   | `1` if a `rx` event occurred. This Event is **level triggered** when the signal |
|       |      | is **high**.                                                                    |
+-------+------+---------------------------------------------------------------------------------+

SERIAL1_EV_ENABLE
^^^^^^^^^^^^^^^^^

`Address: 0xf0003800 + 0x14 = 0xf0003814`

    This register enables the corresponding rx events.  Write a ``0`` to this
    register to disable individual events.

    .. wavedrom::
        :caption: SERIAL1_EV_ENABLE

        {
            "reg": [
                {"name": "tx",  "bits": 1},
                {"name": "rx",  "bits": 1},
                {"bits": 30}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+------+------------------------------------------+
| Field | Name | Description                              |
+=======+======+==========================================+
| [0]   | TX   | Write a ``1`` to enable the ``tx`` Event |
+-------+------+------------------------------------------+
| [1]   | RX   | Write a ``1`` to enable the ``rx`` Event |
+-------+------+------------------------------------------+

SERIAL1_TXEMPTY
^^^^^^^^^^^^^^^

`Address: 0xf0003800 + 0x18 = 0xf0003818`

    TX FIFO Empty.

    .. wavedrom::
        :caption: SERIAL1_TXEMPTY

        {
            "reg": [
                {"name": "txempty", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


SERIAL1_RXFULL
^^^^^^^^^^^^^^

`Address: 0xf0003800 + 0x1c = 0xf000381c`

    RX FIFO Full.

    .. wavedrom::
        :caption: SERIAL1_RXFULL

        {
            "reg": [
                {"name": "rxfull", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


