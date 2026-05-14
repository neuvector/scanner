echo "#############################"
echo "testing rootless keypair only"
echo "#############################"
./sigstore-interface --config-file testing/cases/rootless-keypair-only.json
echo ""

echo "#############################"
echo "testing public keypair"
echo "#############################"
./sigstore-interface --config-file testing/cases/public-keypair.json
echo ""

echo "#############################"
echo "testing suse app collection"
echo "#############################"
./sigstore-interface --config-file testing/cases/suse-app-collection.json