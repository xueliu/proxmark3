SERIAL2
=======

Register Listing for SERIAL2
----------------------------

+------------------------------------------------+----------------------------------------+
| Register                                       | Address                                |
+================================================+========================================+
| :ref:`SERIAL2_RXTX <SERIAL2_RXTX>`             | :ref:`0xf0003000 <SERIAL2_RXTX>`       |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL2_TXFULL <SERIAL2_TXFULL>`         | :ref:`0xf0003004 <SERIAL2_TXFULL>`     |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL2_RXEMPTY <SERIAL2_RXEMPTY>`       | :ref:`0xf0003008 <SERIAL2_RXEMPTY>`    |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL2_EV_STATUS <SERIAL2_EV_STATUS>`   | :ref:`0xf000300c <SERIAL2_EV_STATUS>`  |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL2_EV_PENDING <SERIAL2_EV_PENDING>` | :ref:`0xf0003010 <SERIAL2_EV_PENDING>` |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL2_EV_ENABLE <SERIAL2_EV_ENABLE>`   | :ref:`0xf0003014 <SERIAL2_EV_ENABLE>`  |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL2_TXEMPTY <SERIAL2_TXEMPTY>`       | :ref:`0xf0003018 <SERIAL2_TXEMPTY>`    |
+------------------------------------------------+----------------------------------------+
| :ref:`SERIAL2_RXFULL <SERIAL2_RXFULL>`         | :ref:`0xf000301c <SERIAL2_RXFULL>`     |
+------------------------------------------------+----------------------------------------+

SERIAL2_RXTX
^^^^^^^^^^^^

`Address: 0xf0003000 + 0x0 = 0xf0003000`


    .. wavedrom::
        :caption: SERIAL2_RXTX

        {
            "reg": [
                {"name": "rxtx[7:0]", "bits": 8},
                {"bits": 24},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 1 }, "options": {"hspace": 400, "bits": 32, "lanes": 1}
        }


SERIAL2_TXFULL
^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x4 = 0xf0003004`

    TX FIFO Full.

    .. wavedrom::
        :caption: SERIAL2_TXFULL

        {
            "reg": [
                {"name": "txfull", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


SERIAL2_RXEMPTY
^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x8 = 0xf0003008`

    RX FIFO Empty.

    .. wavedrom::
        :caption: SERIAL2_RXEMPTY

        {
            "reg": [
                {"name": "rxempty", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


SERIAL2_EV_STATUS
^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0xc = 0xf000300c`

    This register contains the current raw level of the rx event trigger.  Writes to
    this register have no effect.

    .. wavedrom::
        :caption: SERIAL2_EV_STATUS

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

SERIAL2_EV_PENDING
^^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x10 = 0xf0003010`

    When a  rx event occurs, the corresponding bit will be set in this register.  To
    clear the Event, set the corresponding bit in this register.

    .. wavedrom::
        :caption: SERIAL2_EV_PENDING

        {
            "reg": [
                {"name": "tx",  "bits": 1},
                {"name": "rx",  "bits": 1},
                {"bits": 30}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+------+------------------------------------------------------------------------------+
| Field | Name | Description                                                                  |
+=======+======+==============================================================================+
| [0]   | TX   | `1` if a `tx` event occurred. This Event is triggered on a **falling** edge. |
+-------+------+------------------------------------------------------------------------------+
| [1]   | RX   | `1` if a `rx` event occurred. This Event is triggered on a **falling** edge. |
+-------+------+------------------------------------------------------------------------------+

SERIAL2_EV_ENABLE
^^^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x14 = 0xf0003014`

    This register enables the corresponding rx events.  Write a ``0`` to this
    register to disable individual events.

    .. wavedrom::
        :caption: SERIAL2_EV_ENABLE

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

SERIAL2_TXEMPTY
^^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x18 = 0xf0003018`

    TX FIFO Empty.

    .. wavedrom::
        :caption: SERIAL2_TXEMPTY

        {
            "reg": [
                {"name": "txempty", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


SERIAL2_RXFULL
^^^^^^^^^^^^^^

`Address: 0xf0003000 + 0x1c = 0xf000301c`

    RX FIFO Full.

    .. wavedrom::
        :caption: SERIAL2_RXFULL

        {
            "reg": [
                {"name": "rxfull", "bits": 1},
                {"bits": 31},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


