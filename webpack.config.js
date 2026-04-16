const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const { InjectManifest } = require('inject-webpack-plugin');
const webpack = require('webpack');

module.exports = (env, argv) => {
    const isProduction = argv.mode === 'production';

    return {
        entry: {
            background: './src/background.js',
            content: './src/content.js',
            popup: './src/popup.js',
            offscreen: './src/offscreen.js'
        },
        output: {
            path: path.resolve(__dirname, 'dist'),
            filename: '[name].js',
            clean: true
        },
        module: {
            rules: [
                {
                    test: /\.js$/,
                    exclude: /node_modules/,
                    use: {
                        loader: 'babel-loader',
                        options: {
                            presets: ['@babel/preset-env']
                        }
                    }
                },
                {
                    test: /\.css$/,
                    use: ['style-loader', 'css-loader']
                }
            ]
        },
        plugins: [
            new CopyWebpackPlugin({
                patterns: [
                    { from: 'manifest.json', to: 'manifest.json', transform: transformManifest },
                    { from: 'libs/openpgp.min.js', to: 'libs/openpgp.min.js' },
                    { from: 'icons', to: 'icons' },
                    { from: 'src/offscreen.html', to: 'content/offscreen.html' }
                ]
            }),
            new HtmlWebpackPlugin({
                template: './src/popup.html',
                filename: 'popup/popup.html',
                chunks: ['popup']
            }),
            new HtmlWebpackPlugin({
                template: './src/popup.css',
                filename: 'popup/popup.css',
                chunks: []
            })
        ],
        resolve: {
            extensions: ['.js']
        },
        optimization: {
            minimize: isProduction,
            splitChunks: {
                chunks: 'all',
                cacheGroups: {
                    vendor: {
                        test: /[\\/]node_modules[\\/]/,
                        name: 'vendors',
                        chunks: 'all'
                    }
                }
            }
        },
        devtool: isProduction ? 'source-map' : 'eval-source-map'
    };
};

function transformManifest(content) {
    const manifest = JSON.parse(content.toString());
    manifest.version = process.env.npm_package_version || '1.0.0';
    if (process.env.NODE_ENV === 'production') {
        delete manifest.content_security_policy;
    }
    return JSON.stringify(manifest, null, 2);
}