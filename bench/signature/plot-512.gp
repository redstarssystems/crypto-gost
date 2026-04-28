set terminal pngcairo size 900,600 font 'DejaVu Sans,12'
set output 'results/ecgost512-throughput.png'

set title 'ECGOST-512 Signature Throughput (TC26-A-512)'
set xlabel 'Operation'
set ylabel 'Throughput (ops/s)'
set yrange [0:*]
set style data histogram
set style histogram cluster gap 2 errorbars linewidth 1.5
set style fill solid 0.85 border -1
set boxwidth 0.8
set grid ytics
set key top right
set bars 2.0

plot 'results/_data-512.tsv' using 2:3:xtic(1) title 'crypto-gost' lt rgb '#2c7bb6', \
     ''                       using 4:5         title 'BouncyCastle 1.83' lt rgb '#d7191c'
