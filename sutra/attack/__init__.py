"""Attack surface (V2): what a firewall or switch configuration lets through, read from the configurations Sutra
already collects (``sutra.app.netconfig``).

* ``fortios``, ``panos`` and ``ios`` turn a collected configuration into a :class:`~sutra.attack.model.Device`.
* ``analyze`` finds the paths from internet, IT and DMZ zones into OT zones across those devices, flags broad,
  shadowed, disabled and unused rules, and ranks the rules whose removal cuts the most paths.
* ``hits`` reads the rule hit counts that "unused" depends on (configurations do not carry them).

Pure library: no database, no web. IPv4 only; dynamic routing (OSPF, BGP) is not modelled.
See ``docs/attack-surface.md``.
"""
