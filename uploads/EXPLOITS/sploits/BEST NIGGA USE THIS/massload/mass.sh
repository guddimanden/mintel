wget https://www.ipdeny.com/ipblocks/data/countries/in.zone
wget https://www.ipdeny.com/ipblocks/data/countries/cn.zone
wget https://www.ipdeny.com/ipblocks/data/countries/jp.zone
wget https://www.ipdeny.com/ipblocks/data/countries/th.zone
wget https://www.ipdeny.com/ipblocks/data/countries/br.zone
wget https://www.ipdeny.com/ipblocks/data/countries/bg.zone
cat *.zone >> zone
cat *.cidr >> cidr
rm -rf *.zone
rm -rf *.cidr
ulimit -n 999999

