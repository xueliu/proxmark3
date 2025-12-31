Interrupt Controller
====================

This device has an ``EventManager``-based interrupt system.  Individual modules
generate `events` which are wired into a central interrupt controller.

When an interrupt occurs, you should look the interrupt number up in the CPU-
specific interrupt table and then call the relevant module.

Assigned Interrupts
-------------------

The following interrupts are assigned on this system:

+-----------+--------------------------+
| Interrupt | Module                   |
+===========+==========================+
| 3         | :doc:`BTN <btn>`         |
+-----------+--------------------------+
| 0         | :doc:`NOIRQ <noirq>`     |
+-----------+--------------------------+
| 4         | :doc:`SERIAL1 <serial1>` |
+-----------+--------------------------+
| 5         | :doc:`SERIAL2 <serial2>` |
+-----------+--------------------------+
| 2         | :doc:`TIMER0 <timer0>`   |
+-----------+--------------------------+
| 6         | :doc:`TIMER1 <timer1>`   |
+-----------+--------------------------+
| 7         | :doc:`TIMER2 <timer2>`   |
+-----------+--------------------------+
| 1         | :doc:`UART <uart>`       |
+-----------+--------------------------+

