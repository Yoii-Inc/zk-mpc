set -ex
trap "exit" INT TERM
trap 'jobs -p | xargs -r kill' EXIT

cargo build --example bin-werewolf --release
BIN=./target/release/examples/bin-werewolf

PROCS=()

mode=$1
players=3

case $mode in
init)
    for i in $(seq 0 $((players - 1))); do
        mkdir -p ./werewolf_game/$i
    done
    RUST_BACKTRACE=1 $BIN init --num-players $players
    wait
    for i in $(seq 0 $((players - 1))); do
        mkdir -p ./werewolf_game/$i
        if [ $i == 0 ]; then
            RUST_BACKTRACE=1 $BIN preprocessing $i ./data/3 &
            pid=$!
            PROCS[$i]=$pid
        else
            $BIN preprocessing $i ./data/3 >/dev/null &
            pid=$!
            PROCS[$i]=$pid
        fi
    done

    for pid in ${PROCS[@]}; do
        wait $pid
    done
    ;;
night)
    if [ ! -f "./werewolf_game/public.json" ]; then
        echo "not found public.json"
        exit 1
    fi
    for i in $(seq 0 $((players - 1))); do
        if [ $i == 0 ]; then
            RUST_BACKTRACE=1 $BIN night --target 1 $i ./data/3 &
            pid=$!
            PROCS[$i]=$pid
        else
            $BIN night $i ./data/3 >/dev/null &
            pid=$!
            PROCS[$i]=$pid
        fi
    done

    for pid in ${PROCS[@]}; do
        wait $pid
    done
    ;;
role_assignment)
    for i in $(seq 0 $((players - 1))); do
        if [ $i == 0 ]; then
            RUST_BACKTRACE=1 $BIN role_assignment $i ./data/3 &
            pid=$!
            PROCS[$i]=$pid
        else
            $BIN role_assignment $i ./data/3 >/dev/null &
            pid=$!
            PROCS[$i]=$pid
        fi
    done

    for pid in ${PROCS[@]}; do
        wait $pid
    done
    ;;
vote)
    for i in $(seq 0 $((players - 1))); do
        if [ $i == 0 ]; then
            RUST_BACKTRACE=1 $BIN vote $i ./data/3 &
            pid=$!
            PROCS[$i]=$pid
        else
            $BIN vote $i ./data/3 >/dev/null &
            pid=$!
            PROCS[$i]=$pid
        fi
    done

    for pid in ${PROCS[@]}; do
        wait $pid
    done
    ;;
judgment)
    for i in $(seq 0 $((players - 1))); do
        if [ $i == 0 ]; then
            RUST_BACKTRACE=1 $BIN judgment $i ./data/3 &
            pid=$!
            PROCS[$i]=$pid
        else
            $BIN judgment $i ./data/3 >/dev/null &
            pid=$!
            PROCS[$i]=$pid
        fi
    done

    for pid in ${PROCS[@]}; do
        wait $pid
    done
    ;;
*)
    echo "invalid mode: $mode"

    echo "Usage: $0 [init|mode]"
    exit 1
    ;;
esac

echo done
