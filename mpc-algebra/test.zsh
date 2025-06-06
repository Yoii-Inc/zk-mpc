set -ex
trap "exit" INT TERM
trap "kill 0" EXIT

# Move to the project directory
cd "$(dirname "$0")"

# Execute cargo build command
cargo build --example algebra --release
BIN="$(pwd)/target/release/examples/algebra"

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