set -ex
trap "exit" INT TERM
trap "kill 0" EXIT

if [[ $1 == "algebra" ]]; then
cargo build --example algebra
elif [[ $1 == "r1cs" ]]; then
cargo build --example r1cs
else
    echo "Invalid argument. Usage: ./test.zsh [algebra|r1cs]"
    exit
fi

BIN="./target/debug/examples/$1"


PROCS=()

for i in $(seq 0 2)
do
if [ $i == 0 ]
then
    RUST_BACKTRACE=1  $BIN $i ./data/address &
    pid=$!
    PROCS[$i]=$pid
else
    $BIN $i ./data/address > /dev/null &
    pid=$!
    PROCS[$i]=$pid
fi
done

for pid in ${PROCS[@]}
do
wait $pid
done

echo done