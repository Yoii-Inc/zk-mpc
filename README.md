This repositry is zk-mpc.

## Directory Structure
- input_circuit.rs
    - This file defines the input circuit for prove the correctness of secret inputs sharing.
- preprocess.rs
    - This file defines the preprocessing module.
    - MPC protocol requires preprocessing.
- she.rs
    - This file defines the Somewhat Hmomorphic Encryption protocol. Concrete implementation is based on these papers.
        - [Fully Homomorphic Encryption from Ring-LWE
and Security for Key Dependent Messages](https://www.wisdom.weizmann.ac.il/~zvikab/localpapers/IdealHom.pdf).
        - [Fully Homomorphic SIMD Operations
](https://eprint.iacr.org/2011/133.pdf).
        - [Multiparty Computation from Somewhat Homomorphic
Encryption](https://eprint.iacr.org/2011/535.pdf).

## Build guide
Clone this repositry:
```
git clone https://github.com/Yoii-Inc/zk-mpc.git
```

and build:
```
cargo build
```

run:
```
cargo run ./inputs/inputs.json
```

## Tests

```
cargo test
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

    ``` rust
    struct ArgInput {
        arg1: u128,
        arg2: i32,
        arg3: String,
    }
    ```
    Modify the ArgInput struct as needed to accommodate the changes in the number and types of arguments.

By following these steps, you can specify secret inputs in the inputs.json file and receive them in your Rust program using the ArgInput struct.

### how to specify constraints


## Technical Details
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