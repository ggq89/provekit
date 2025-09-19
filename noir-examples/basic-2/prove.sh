nargo compile
nargo check
nargo execute my-witness
bb prove -b ./target/basic.json -w ./target/my-witness.gz -o ./target
echo "✅ Proof generated at ./target/proof"
bb write_vk -b ./target/basic.json -o ./target
bb verify -k ./target/vk -p ./target/proof -i ./target/public_inputs
echo "✅ Verified the proof at ./target/proof"
bb gates -b ./target/basic.json
echo "✅ Circuit has been analyzed"
