set -ex
trap "exit" INT TERM
trap 'jobs -p | xargs -r kill' EXIT

cargo build --example online --release
BIN=./target/release/examples/online


PROCS=()

for i in $(seq 0 2)
do
if [ $i == 0 ]
then
    RUST_BACKTRACE=1  $BIN marlin ./inputs/inputs.json $i ./data/address &
    pid=$!
    PROCS[$i]=$pid
else
    $BIN marlin ./inputs/inputs.json $i ./data/address > /dev/null &
    pid=$!
    PROCS[$i]=$pid
fi
done

for pid in ${PROCS[@]}
do
wait $pid
done

echo done