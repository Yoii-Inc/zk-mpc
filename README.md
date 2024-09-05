This repositry is zk-mpc.

## Directory Structure

The following is the main directory structure.

```
.
|-- Cargo.lock
|-- Cargo.toml
|-- README.md
|-- arkworks                     # Arkworks libraries
|-- benches                      # Benchmarking
|-- data
|   `-- address
|-- docs                         # subDocuments
|   `-- benchmark.md             # Benchmarking results
|-- examples                     # Binary files are here.
|   |-- bin_test_groth16.rs
|   |-- bin_test_marlin.rs
|   |-- bin_werewolf.rs          # Werewolf game binary file.
|   `-- online.rs                # Online phase (in MPC) binary file.
|-- images                       # Image assets
|-- inputs
|   |-- inputs-template.json
|   `-- inputs.json
|-- mpc-algebra                  # Sub crate: MPC algebra. MpcField, MpcVar, etc.
|   |-- Cargo.lock
|   |-- Cargo.toml
|   |-- README.md
|   |-- data
|   |-- examples
|   |-- src
|   `-- test.zsh
|-- mpc-net                      # Sub crate: MPC network. MpcNet, MpcNetServer, etc.
|   |-- Cargo.lock
|   |-- Cargo.toml
|   |-- data
|   |-- examples
|   `-- src
|-- mpc-trait
|   |-- Cargo.toml
|   `-- src
|-- run_groth16.zsh              # Script for Run groth16
|-- run_marlin.zsh               # Script for Run marlin
|-- run_online.zsh               # Script for Run online phase
|-- run_werewolf.zsh             # Script for Run werewolf game
`-- src
    |-- algebra.rs
    |-- circuits                 # Circuits modules. Various circuits are defined here.
    |-- circuits.rs
    |-- groth16.rs               # Groth16(zk-SNARKs) module
    |-- input.rs                 # Input structs are defined in circuits.
    |-- lib.rs
    |-- main.rs                  # Main binary file used for preprocessing phase.
    |-- marlin.rs                # Marlin(zk-SNARKs) module
    |-- preprocessing.rs         # Preprocessing module, which is required for MPC.
    |-- serialize.rs
    |-- she                      # Somewhat Homomorphic Encryption sub module.
    `-- she.rs                   # Somewhat Homomorphic Encryption
```

## Build guide

Clone this repositry:

```bash
git clone https://github.com/Yoii-Inc/zk-mpc.git
```

and build:

```bash
cargo build
```

setup input file

```bash
cp ./inputs/inputs-template.json ./inputs/inputs.json
```

### Preprocessing phase

setup output folder

```
mkdir ./outputs
mkdir ./outputs/0
mkdir ./outputs/1
mkdir ./outputs/2
```

run(by groth16):

```bash
cargo run --bin main groth16 ./inputs/inputs.json
```

or run(by marlin):

```bash
cargo run --bin main marlin ./inputs/inputs.json
```

### Online phase

run online phase

```bash
./run_online.zsh
```

## Tests

### Non-MPC tests

The tests performed by the following **DOES NOT** include MPC. Therefore, testing of the MPC itself is performed by executing preprocessing and online as described above.

```bash
cargo test --bin main
```

### MPC tests

```bash
./run_marlin.zsh
```

or

```bash
./mpc-algebra/test.zsh
```

## Usage

### how to specify secret inputs

To specify secret inputs, follow these steps:

1. In the `inputs/inputs.json` file, define the desired inputs using a JSON format. For example:

   ```json
   {
     "arg1": 10,
     "arg2": -2,
     "arg3": "value3"
   }
   ```

   You can modify the number and types of arguments based on your requirements.

2. In the main.rs file of your project, use the ArgInput struct to receive the specified arguments. Make sure to update the struct definition to match the number and types of arguments you specified in the inputs.json file. For example:

   ```rust
   struct ArgInput {
       arg1: u128,
       arg2: i32,
       arg3: String,
   }
   ```

   Modify the ArgInput struct as needed to accommodate the changes in the number and types of arguments.

By following these steps, you can specify secret inputs in the inputs.json file and receive them in your Rust program using the ArgInput struct.

### how to specify constraints

Constraints are specified in `input_circuit.rs`. For example:

```rust
pub struct MySecretInputCircuit<F: PrimeField + LocalOrMPC<F>> {
    // private witness to the circuit
    x: Option<F>,
    input_bit: Option<Vec<F>>,
    open_bit: Option<Vec<F>>,
    params: Option<F::PedersenParam>,

    // public instance to the circuit
    h_x: Option<F::PedersenCommitment>,
    lower_bound: Option<F>,
    upper_bound: Option<F>,
}
```

This sturuct represents a circuit, and it requires to define the necessary witness and public instances.

In addition, the constraints in the circuit are defined as follows.

```rust
impl<F: PrimeField + LocalOrMPC<F>> ConstraintSynthesizer<F> for MySecretInputCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        self.verify_constraints(cs.clone())?;

        self.verify_commitment(cs.clone())?;

        Ok(())
    }
}
```

In addition to usual constraints, we also defines one here to calculate commitments.

Here we show the example of the former constraints:

```rust
impl<F: PrimeField + LocalOrMPC<F>> MySecretInputCircuit<F> {
    fn verify_constraints(&self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x = FpVar::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let lower_bound = FpVar::new_input(cs.clone(), || {
            self.lower_bound.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let upper_bound = FpVar::new_input(cs.clone(), || {
            self.upper_bound.ok_or(SynthesisError::AssignmentMissing)
        })?;

        x.enforce_cmp(&lower_bound, Ordering::Greater, true)?;
        x.enforce_cmp(&upper_bound, Ordering::Less, false)?;

        Ok(())
    }
}
```

See [this](https://github.com/arkworks-rs/r1cs-tutorial/) to learn more about how to specify constraints.

### how to specify mpc calculation

online mpc calculations are specified in `circuits/circuit.rs`. Defaultly, MySimpleCircuit is used. Constraints is specified in same way as `input_circuit.rs`.

## Example - Werewolf

Initialize werewolf game. The following command initializes the game with 3 players. Game files are generated in `werewolf/` directory.

```
./run_werewolf.zsh init 3
```

Run the game. The following command runs the game in the night phase.
The command is written in Default zsh file, that player allocated `fortune teller` get whether next player is werewolf or not and outputs the result to e.g. `werewolf/0/divination_result.json`.

```
./run_werewolf.zsh night
```

## Technical Details

### SHE (Somewhat Homomorphic Encryption) protocol

In `she` module, we implement somewhat homomorphic encryption. Concrete implementation is based on these papers.

- [Fully Homomorphic Encryption from Ring-LWE
  and Security for Key Dependent Messages](https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf).
- [Fully Homomorphic SIMD Operations
  ](https://eprint.iacr.org/2011/133.pdf).
- [Multiparty Computation from Somewhat Homomorphic
  Encryption](https://eprint.iacr.org/2011/535.pdf).

### Generating secret sharing of inputs and ZKP verification

The additive secret sharing method is used in SPDZ, and the secret information $S$ is kept in the form of shares $S_i$ such that

$$S=\sum_{i=1}^nS_i$$

With respect to the input values of SPDZ, a participant's share of secret information $X$ is constructed as follows.

1. Each participant has a share $r_i$ of a random number $r$. The value of $r$ is unknown to anyone at this point.
2. The participant who wants to create a share of secret information $x$ recovers the value of $r$ and broadcasts $\varepsilon=x-r$.
3. Each participant $P_i$ determines its share $x_i$ of $x$ as $x_1=r_1+\varepsilon, x_i=r_i(i\neq 1)$. In this case, $x=\sum x_i$ holds.

The share $x_i$ is created by such a procedure, but it is not generally known whether each participant has composed the share according to the protocol, or whether the original secret information $x$ satisfies certain conditions.

Therefore, for each conditional secret input $x$, we use zkp to prove that each person's share of $x$ has been correctly created.

- Secret input
  - $x$: secret information
  - $randomenesss$: randomness for commitment.
- Public input
  - $h_x$: commitment of secret value $x$.

For these, the participant who has secret inputs creates a proof so that the following relation is satisfied.

$$
\begin{align*}
C(x)&=0\\
Commitment(x, randomeness)&=h_x
\end{align*}
$$

where the 1st equation is the condition that $x$ must satisfy.

Requirement for $r$ and $\varepsilon$ isn't necessary, since SPDZ protocol has MAC verification for authenticated shares.s

## Benchmarking

Result of benchmarking is shown in [benchmark.md](./docs/benchmark.md).
