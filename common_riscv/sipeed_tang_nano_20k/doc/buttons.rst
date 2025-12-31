BUTTONS
=======

Register Listing for BUTTONS
----------------------------

+------------------------------------------------+----------------------------------------+
| Register                                       | Address                                |
+================================================+========================================+
| :ref:`BUTTONS_IN <BUTTONS_IN>`                 | :ref:`0xf0000800 <BUTTONS_IN>`         |
+------------------------------------------------+----------------------------------------+
| :ref:`BUTTONS_MODE <BUTTONS_MODE>`             | :ref:`0xf0000804 <BUTTONS_MODE>`       |
+------------------------------------------------+----------------------------------------+
| :ref:`BUTTONS_EDGE <BUTTONS_EDGE>`             | :ref:`0xf0000808 <BUTTONS_EDGE>`       |
+------------------------------------------------+----------------------------------------+
| :ref:`BUTTONS_EV_STATUS <BUTTONS_EV_STATUS>`   | :ref:`0xf000080c <BUTTONS_EV_STATUS>`  |
+------------------------------------------------+----------------------------------------+
| :ref:`BUTTONS_EV_PENDING <BUTTONS_EV_PENDING>` | :ref:`0xf0000810 <BUTTONS_EV_PENDING>` |
+------------------------------------------------+----------------------------------------+
| :ref:`BUTTONS_EV_ENABLE <BUTTONS_EV_ENABLE>`   | :ref:`0xf0000814 <BUTTONS_EV_ENABLE>`  |
+------------------------------------------------+----------------------------------------+

BUTTONS_IN
^^^^^^^^^^

`Address: 0xf0000800 + 0x0 = 0xf0000800`

    GPIO Input(s) Status.

    .. wavedrom::
        :caption: BUTTONS_IN

        {
            "reg": [
                {"name": "in[1:0]", "bits": 2},
                {"bits": 30},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


BUTTONS_MODE
^^^^^^^^^^^^

`Address: 0xf0000800 + 0x4 = 0xf0000804`

    GPIO IRQ Mode: 0: Edge, 1: Change.

    .. wavedrom::
        :caption: BUTTONS_MODE

        {
            "reg": [
                {"name": "mode[1:0]", "bits": 2},
                {"bits": 30},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


BUTTONS_EDGE
^^^^^^^^^^^^

`Address: 0xf0000800 + 0x8 = 0xf0000808`

    GPIO IRQ Edge (when in Edge mode): 0: Rising Edge, 1: Falling Edge.

    .. wavedrom::
        :caption: BUTTONS_EDGE

        {
            "reg": [
                {"name": "edge[1:0]", "bits": 2},
                {"bits": 30},
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


BUTTONS_EV_STATUS
^^^^^^^^^^^^^^^^^

`Address: 0xf0000800 + 0xc = 0xf000080c`

    This register contains the current raw level of the i1 event trigger.  Writes to
    this register have no effect.

    .. wavedrom::
        :caption: BUTTONS_EV_STATUS

        {
            "reg": [
                {"name": "i0",  "bits": 1},
                {"name": "i1",  "bits": 1},
                {"bits": 30}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+------+---------------------------+
| Field | Name | Description               |
+=======+======+===========================+
| [0]   | I0   | Level of the ``i0`` event |
+-------+------+---------------------------+
| [1]   | I1   | Level of the ``i1`` event |
+-------+------+---------------------------+

BUTTONS_EV_PENDING
^^^^^^^^^^^^^^^^^^

`Address: 0xf0000800 + 0x10 = 0xf0000810`

    When a  i1 event occurs, the corresponding bit will be set in this register.  To
    clear the Event, set the corresponding bit in this register.

    .. wavedrom::
        :caption: BUTTONS_EV_PENDING

        {
            "reg": [
                {"name": "i0",  "bits": 1},
                {"name": "i1",  "bits": 1},
                {"bits": 30}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+------+------------------------------------------------------------------------------+
| Field | Name | Description                                                                  |
+=======+======+==============================================================================+
| [0]   | I0   | `1` if a `i0` event occurred. This Event is triggered on a **falling** edge. |
+-------+------+------------------------------------------------------------------------------+
| [1]   | I1   | `1` if a `i1` event occurred. This Event is triggered on a **falling** edge. |
+-------+------+------------------------------------------------------------------------------+

BUTTONS_EV_ENABLE
^^^^^^^^^^^^^^^^^

`Address: 0xf0000800 + 0x14 = 0xf0000814`

    This register enables the corresponding i1 events.  Write a ``0`` to this
    register to disable individual events.

    .. wavedrom::
        :caption: BUTTONS_EV_ENABLE

        {
            "reg": [
                {"name": "i0",  "bits": 1},
                {"name": "i1",  "bits": 1},
                {"bits": 30}
            ], "config": {"hspace": 400, "bits": 32, "lanes": 4 }, "options": {"hspace": 400, "bits": 32, "lanes": 4}
        }


+-------+------+------------------------------------------+
| Field | Name | Description                              |
+=======+======+==========================================+
| [0]   | I0   | Write a ``1`` to enable the ``i0`` Event |
+-------+------+------------------------------------------+
| [1]   | I1   | Write a ``1`` to enable the ``i1`` Event |
+-------+------+------------------------------------------+

