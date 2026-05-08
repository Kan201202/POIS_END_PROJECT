"""
PA#20: Boolean circuit evaluator + Millionaire's Problem
"""
from src.mpc.secure_and import secure_and, secure_xor, secure_not

class Circuit:
    def __init__(self):
        self.gates = []  # list of (gate_type, in1, in2, out)
        self.num_wires = 0

    def add_input(self):
        w = self.num_wires
        self.num_wires += 1
        return w

    def add_and(self, a, b):
        out = self.num_wires
        self.num_wires += 1
        self.gates.append(('AND', a, b, out))
        return out

    def add_xor(self, a, b):
        out = self.num_wires
        self.num_wires += 1
        self.gates.append(('XOR', a, b, out))
        return out

    def add_not(self, a):
        out = self.num_wires
        self.num_wires += 1
        self.gates.append(('NOT', a, None, out))
        return out

    def evaluate(self, wire_values: dict) -> dict:
        """Evaluate circuit securely gate by gate."""
        vals = dict(wire_values)
        for gate_type, in1, in2, out in self.gates:
            if gate_type == 'AND':
                vals[out] = secure_and(vals[in1], vals[in2])
            elif gate_type == 'XOR':
                vals[out] = secure_xor(vals[in1], vals[in2])
            elif gate_type == 'NOT':
                vals[out] = secure_not(vals[in1])
        return vals


def millionaires(x: int, y: int, n_bits: int = 4) -> str:
    """
    Securely compute x > y without revealing x or y.
    Uses ripple-carry comparator circuit built from AND/XOR/NOT gates.
    Returns 'Alice' if x > y, 'Bob' if y > x, 'Equal' if x == y.
    """
    c = Circuit()

    # Input wires: x bits and y bits (MSB first)
    x_wires = [c.add_input() for _ in range(n_bits)]
    y_wires = [c.add_input() for _ in range(n_bits)]

    # Wire values
    wire_vals = {}
    for i in range(n_bits):
        wire_vals[x_wires[i]] = (x >> (n_bits - 1 - i)) & 1
        wire_vals[y_wires[i]] = (y >> (n_bits - 1 - i)) & 1

    # Comparator: gt=1 means x>y so far, eq=1 means equal so far
    # Start: gt=0, eq=1 (nothing compared yet)
    gt_wire = c.add_xor(x_wires[0], x_wires[0])  # wire = 0
    wire_vals[gt_wire] = 0
    eq_wire = c.add_not(gt_wire)                  # wire = 1
    wire_vals[eq_wire] = 1

    for i in range(n_bits):
        xi = x_wires[i]
        yi = y_wires[i]
        not_yi = c.add_not(yi)

        # x_gt_y_here = xi AND (NOT yi)
        x_gt_here = c.add_and(xi, not_yi)
        # new_gt = old_gt OR (eq AND x_gt_here)
        # OR(a,b) = NOT(NOT(a) AND NOT(b))
        eq_and_gt = c.add_and(eq_wire, x_gt_here)
        not_old_gt = c.add_not(gt_wire)
        not_eq_and_gt = c.add_not(eq_and_gt)
        new_gt = c.add_not(c.add_and(not_old_gt, not_eq_and_gt))

        # new_eq = eq AND (xi XNOR yi) = eq AND NOT(xi XOR yi)
        xor_bits = c.add_xor(xi, yi)
        xnor_bits = c.add_not(xor_bits)
        new_eq = c.add_and(eq_wire, xnor_bits)

        gt_wire = new_gt
        eq_wire = new_eq

    result = c.evaluate(wire_vals)

    if result[eq_wire] == 1:
        return 'Equal'
    elif result[gt_wire] == 1:
        return 'Alice'
    else:
        return 'Bob'


def secure_equality(x: int, y: int, n_bits: int = 4) -> bool:
    """Securely compute x == y."""
    c = Circuit()
    x_wires = [c.add_input() for _ in range(n_bits)]
    y_wires = [c.add_input() for _ in range(n_bits)]
    wire_vals = {}
    for i in range(n_bits):
        wire_vals[x_wires[i]] = (x >> i) & 1
        wire_vals[y_wires[i]] = (y >> i) & 1

    # All bits must be equal: AND of XNOR for each bit
    eq_bits = []
    for i in range(n_bits):
        xor_w = c.add_xor(x_wires[i], y_wires[i])
        xnor_w = c.add_not(xor_w)
        eq_bits.append(xnor_w)

    result_wire = eq_bits[0]
    for i in range(1, n_bits):
        result_wire = c.add_and(result_wire, eq_bits[i])

    result = c.evaluate(wire_vals)
    return bool(result[result_wire])


def secure_add(x: int, y: int, n_bits: int = 4) -> int:
    """Securely compute x + y mod 2^n using full adder circuit."""
    c = Circuit()
    x_wires = [c.add_input() for _ in range(n_bits)]
    y_wires = [c.add_input() for _ in range(n_bits)]
    wire_vals = {}
    for i in range(n_bits):
        wire_vals[x_wires[i]] = (x >> i) & 1
        wire_vals[y_wires[i]] = (y >> i) & 1

    # Ripple-carry adder
    carry_wire = c.add_xor(x_wires[0], x_wires[0])  # carry = 0
    wire_vals[carry_wire] = 0
    sum_wires = []

    for i in range(n_bits):
        # sum bit = x XOR y XOR carry
        xor1 = c.add_xor(x_wires[i], y_wires[i])
        sum_w = c.add_xor(xor1, carry_wire)
        sum_wires.append(sum_w)
        # carry = (x AND y) OR (carry AND (x XOR y))
        and1 = c.add_and(x_wires[i], y_wires[i])
        and2 = c.add_and(carry_wire, xor1)
        # OR via NOT(NOT(a) AND NOT(b))
        not1 = c.add_not(and1)
        not2 = c.add_not(and2)
        carry_wire = c.add_not(c.add_and(not1, not2))

    result = c.evaluate(wire_vals)
    total = 0
    for i, sw in enumerate(sum_wires):
        total |= result[sw] << i
    return total