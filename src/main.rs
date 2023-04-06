/*
 * HARVEST (High-speed Asynchronous Rust Vocabulary Extraction and Search Tool) is an OSINT tool to recursively 
 * crawl through a supplied web page, and gather useful information including a wordlist of less-common words 
 * found, a list of email addresses found, a list of social media accounts found, and more.
 * 
 * Author: Ember Hext
 * GitHub: https://github.com/EmberHext
 * Twitter: @EmberHext
 * 
 * It is released under the MIT License:
 * 
 * Copyright 2023 Ember Hext
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
 * documentation files (the “Software”), to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and 
 * to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * 
 * Note: This is intended to be used for your own servers or in contexts like pentesting and CTFs where you are authorised 
 * to be engaging with the server in this manner.
 * 
 */

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(name = "harvest")]
#[command(author = "Ember Hext <github.com/EmberHext")]
#[command(version = "1.0")]
#[command(about = "Crawl through a website for interesting words and more", long_about = "Crawl through a website for interesting words, email addresses, and social media links")]
struct Cli {
    /// Link to page to search
    url: String,
    /// File to output wordlist into
    #[arg(short, long = "file", value_name = "FILE")]
    wlfile: Option<String>,
    /// Do not output a wordlist
    #[arg(short, long)]
    nowords: bool,
    /// Find all emails
    #[arg(short, long)]
    email: bool,
    /// File to output emails into
    #[arg(long, value_name = "FILE")]
    emfile: Option<String>,
    /// Find all socials
    #[arg(short, long)]
    social: bool,
    /// File to output socials into
    #[arg(long, value_name = "FILE")]
    socfile: Option<String>,
    /// Depth to crawl, default is 2
    #[arg(short, long, value_name="x")]
    depth: Option<u8>,
    /// Minimum word length, default is 4
    #[arg(short, long, value_name="x")]
    min: Option<u8>,
}

fn main() {
    let _args = Cli::parse();
}
