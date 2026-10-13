const { InferenceClient } = await import("@huggingface/inference");
const fs = await import("fs");

const hf = new InferenceClient(process.env.HUGGINGFACE_TOKEN);

console.log("Generating image...");

const image = await hf.textToImage({
  model: "black-forest-labs/FLUX.1-schnell",
  inputs: "a futuristic friendly AI robot named Curio, dark neon computer room"
});

fs.writeFileSync("test.png", Buffer.from(await image.arrayBuffer()));

console.log("SUCCESS! Image saved as test.png");