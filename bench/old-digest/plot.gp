set terminal pngcairo size 1000,650 enhanced font 'DejaVu Sans,11'
set output 'results/streebog256-throughput.png'
set title 'Streebog-256: сравнение производительности'
set xlabel 'Размер данных (байт)'
set ylabel 'Throughput (MB/s)'
set logscale x
set grid
set key top left
set datafile separator '\t'
set style data linespoints

plot 'results/data-gost.tsv' using 1:2:3 with yerrorlines \
    title 'crypto-gost v0.1.2' linewidth 2 pointtype 7 pointsize 1.5 lc rgb '#0066cc', \
    'results/data-bc.tsv' using 1:2:3 with yerrorlines \
    title 'BouncyCastle 1.83' linewidth 2 pointtype 9 pointsize 1.5 lc rgb '#cc3300'
