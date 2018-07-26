#!/bin/bash

source ctypes.sh

dlopen "libc.so.6"

# mem_read pid localaddr remoteaddr size
# moved outside, allocating the struct everytime causes a huge performance impact
struct -m p_mlocal iovec mlocal
struct -m p_mremote iovec mremote
function mem_read() {

	local p_pid=`toraw $1`
	local localaddr=`toraw $2`
	local remoteaddr=`toraw $3`
	local size=`toraw $4`

	mlocal[iov_base]="long:$localaddr"
	mlocal[iov_len]="long:$size"

	mremote[iov_base]="long:$remoteaddr"
	mremote[iov_len]="long:$size"

	pack $p_mlocal mlocal
	pack $p_mremote mremote

	dlcall -h ${DLHANDLES[libc.so.6]} -r long process_vm_readv $p_pid $p_mlocal 1 $p_mremote 1 0
}

function mem_write() {

	local p_pid=`toraw $1`
	local localaddr=`toraw $2`
	local remoteaddr=`toraw $3`
	local size=`toraw $4`

	mlocal[iov_base]="long:$localaddr"
	mlocal[iov_len]="long:$size"

	mremote[iov_base]="long:$remoteaddr"
	mremote[iov_len]="long:$size"

	pack $p_mlocal mlocal
	pack $p_mremote mremote

	dlcall -h ${DLHANDLES[libc.so.6]} -r long process_vm_writev $p_pid $p_mlocal 1 $p_mremote 1 0
}

# find_sig PID startaddr endaddr "sig"
function find_sig() {
	CHUNK_SIZE=524288

	local p_pid=`toraw $1`
	local startaddr=`toraw $2`
	local endaddr=`toraw $3`
	local pos=0
	local sig="$4"

	dlcall -n chunkbuf -r pointer malloc long:$CHUNK_SIZE

	mlocal[iov_len]="long:$CHUNK_SIZE"
	mremote[iov_len]="long:$CHUNK_SIZE"
	mlocal[iov_base]=$chunkbuf
	pack $p_mlocal mlocal

	sig="${sig,,}"
	sigb=($sig)

	local matches=0
	while [[ $(( $startaddr + $pos )) < $endaddr ]]; do
		#echo "$pos / $(( $endaddr - $startaddr ))"
		while read -r line; do
			if [[ "$line" == "${sigb[$matches]}" ]] || [[ "${sigb[$matches]}" == "??" ]]; then
				let matches++
				if [[ "$matches" -eq "${#sigb[@]}" ]]; then
					pos=$(( $pos - $matches + 1))
					echo "$pos"
					return
				fi
			else
				matches=0
			fi
			let pos++
		done <<< $(xxd -p -l$CHUNK_SIZE -c1 -s $(( $startaddr + $pos )) /proc/$p_pid/mem)
	done
}

# GetAbsoluteAddress pid address offset size
function GetAbsoluteAddress() {
	local p_pid=`toraw $1`
	local addr=`toraw $2`
	local offset=`toraw $3`
	local size=`toraw $3`

	sizeof -m code int
	mem_read $PROC_PID $code $(( $addr + $offset )) 4

	echo $(( `deref int $code` + $addr + $size + 4 ))
}

function GetCallAddress() {
	GetAbsoluteAddress "$1" "$2" 1 5
}

# deref int/long addr
# *x
function deref() {
	tmp_ptr=( "$1" )
	unpack $2 tmp_ptr
	echo ${tmp_ptr#*:}
}

# deref_w int/long addr newval
# *x = $3
function deref_w() {
	tmp_ptr=( "$1:$3" )
	pack $2 tmp_ptr
}

function toraw() {
	val=${1#*:}
	if [[ "$val" =~ ^0x.* ]]; then
    	val=$(( 16#${val#*x} ))
	fi
	echo $val
}

PROC_NAME="csgo_linux64"
PROC_PID=`pidof "$PROC_NAME"`
IFS='-' read -ra PROC_ADDRS <<<  $(grep "r-xp" /proc/$PROC_PID/maps|grep "client_client.so"|grep -o '^\S*')
PROC_START=$(( 16#${PROC_ADDRS[0]} ))
PROC_END=$(( 16#${PROC_ADDRS[1]} ))

echo "PROC_START: $PROC_START"
echo "PROC_END: $PROC_END"
#X_LP_LEA=$(find_sig $PROC_PID $PROC_START $PROC_END "48 89 e5 74 0e 48 8d 05 ?? ?? ?? ??")
X_LP_LEA=7459131
X_LP_PTR=`GetCallAddress $PROC_PID $(( $PROC_START + $X_LP_LEA + 7 ))`

#X_ALT1_MOV=$(find_sig $PROC_PID $PROC_START $PROC_END "89 D8 80 CC 40 F6 C2 03 0F 45 D8 44 89 ?? C1 E0 11 C1 F8 1F 83 E8 03")
X_ALT1_MOV=8743393
X_ALT1=`GetAbsoluteAddress $PROC_PID $(( $PROC_START + $X_ALT1_MOV - 7 )) 3 7`
X_JUMP=$(( $X_ALT1 + 12 * 5 ))

sizeof -m _X_LP_TMP long
mem_read $PROC_PID $_X_LP_TMP $X_LP_PTR 8
X_LP=`deref long $_X_LP_TMP`

X_LP_m_fFlags=$(( $X_LP + 16#138 ))
sizeof -m m_fFlags_ptr int

sizeof -m alt1_ptr int

sizeof -m down_ptr int
deref_w int $down_ptr 5
sizeof -m release_ptr int
deref_w int $release_ptr 4

while true; do
	mem_read $PROC_PID $alt1_ptr $X_ALT1 4
	if [[ `deref int $alt1_ptr` -eq 5 ]]; then

		mem_read $PROC_PID $m_fFlags_ptr $X_LP_m_fFlags 4
		if (( (`deref int $m_fFlags_ptr` & 1) == 1 )); then

			mem_write $PROC_PID $down_ptr $X_JUMP 4
			sleep 0.005
			mem_write $PROC_PID $release_ptr $X_JUMP 5
		fi	
	fi
done

