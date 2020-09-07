const webpack = require("webpack");
const path = require("path");
const devConfig = require("./webpack.dev.config");
const prodConfig = require("./webpack.prod.config");

const {
  SRC_DIR,
  BUILD_DIR,
  isDevelopment,
  isProduction
} = require("./constants");

const baseConfig = {
  devtool: "source-map",
  node: {
    process: false
  },
  entry: {
    index: path.resolve(SRC_DIR, "index.ts")
  },
  output: {
    filename: "[name].js",
    path: BUILD_DIR,
    libraryTarget: "umd",
    globalObject: "this"
  },
  externals: {
    'bn.js': 'bn.js',
    'elliptic': 'elliptic',
    'base85': 'base85',
    'crypto-js': 'crypto-js',
  },
  resolve: {
    extensions: [".ts", ".json", ".js"]
  },
  plugins: [
    new webpack.DefinePlugin({
      "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV)
    })
  ],
  module: {
    rules: [
      {
        test: /\.ts$/,
        exclude: /node_modules/,
        use: {
          loader: "ts-loader"
        }
      }
    ]
  }
};

let config = null;

if (isProduction) {
  config = prodConfig(baseConfig);
} else if (isDevelopment) {
  config = devConfig(baseConfig);
}

module.exports = config;
