set -ex
trap "exit" INT TERM
trap 'jobs -p | xargs -r kill' EXIT

cargo build --example bin-test-marlin --release 
BIN=./target/release/examples/bin-test-marlin


PROCS=()

for i in $(seq 0 2)
do
if [ $i == 0 ]
then
    RUST_BACKTRACE=1  $BIN $i ./data/3 &
    pid=$!
    PROCS[$i]=$pid
else
    $BIN $i ./data/3 > /dev/null &
    pid=$!
    PROCS[$i]=$pid
fi
done

for pid in ${PROCS[@]}
do
wait $pid
done

echo done