set terminal pngcairo size 900,600 font 'DejaVu Sans,12'
set output 'results/kuznyechik-cfb-throughput.png'

set title 'Kuznyechik CFB Mode — Throughput'
set xlabel 'Buffer size'
set ylabel 'Throughput (MB/s)'
set yrange [0:*]
set grid ytics
set style data histogram
set style histogram cluster gap 2 errorbars linewidth 1.5
set style fill solid 0.85 border -1
set boxwidth 0.8
set key top left
set bars 2.0

plot 'results/_data-cfb.tsv' using 2:3:xtic(1) title 'crypto-gost' lt rgb '#2c7bb6', \
     ''                       using 4:5         title 'BouncyCastle 1.83' lt rgb '#d7191c'
