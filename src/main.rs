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
use std::{
    collections::HashMap,
    fs::File,
    io::{
        BufRead,
        BufReader,
    },
    path::Path,
};
use reqwest::blocking::get;
use select::{
    document::Document,
    predicate::{
        Name,
        Predicate,
    }
};
use regex::Regex;
use std::sync::Arc;
use select::node::Node;

struct Or(Vec<Box<dyn Predicate>>);

impl Predicate for Or {
    fn matches(&self, node: &Node) -> bool {
        self.0.iter().any(|predicate| predicate.matches(node))
    }
}

fn unique_words_from_url(url: &str, common_words_to_ignore: usize) -> Result<HashMap<String, u32>, Box<dyn std::error::Error>> {
    let common_words_file_path = Path::new("src/resources/commonwords.txt");
    let file = File::open(&common_words_file_path)?;
    let reader = BufReader::new(file);
    let mut common_words = Vec::new();

    for (i, line) in reader.lines().enumerate() {
        if i >= common_words_to_ignore {
            break;
        }
        let line = line?;
        common_words.push(line.to_lowercase());
    }

    let mut word_counts = HashMap::new();

    let resp = reqwest::blocking::get(url)?;
    let document = Document::from_read(resp)?;

    let tags = vec![
        Name("h1"), Name("h2"), Name("h3"), Name("h4"), Name("h5"), Name("h6"),
        Name("p"), Name("li"), Name("dt"), Name("dd"), Name("blockquote"), Name("q"), Name("cite"),
        Name("caption"), Name("th"), Name("td"), Name("pre"), Name("code"), Name("strong"), Name("em"),
        Name("mark"), Name("small"), Name("del"), Name("ins"), Name("sub"), Name("sup"), Name("a"),
    ];

    let or_predicate = Or(tags.into_iter().map(|tag| Box::new(tag) as Box<dyn Predicate>).collect());

    let elements = document.find(or_predicate);
    let text = elements.map(|n| n.text()).collect::<Vec<_>>().join(" ");

    let word_regex = Regex::new(r"\b[a-zA-Z]+\b").unwrap();
    let words = word_regex.find_iter(&text)
        .map(|m| m.as_str().to_lowercase())
        .filter(|word| !common_words.contains(word));

    for word in words {
        let count = word_counts.entry(word).or_insert(0);
        *count += 1;
    }

    Ok(word_counts)
}


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
    /// The number of most common words to filter, default is 400, max is 1000
    #[arg(short, long, value_name="x")]
    common: Option<u8>,
    /// Allow the crawler to follow external links
    #[arg(short, long)]
    offsite: bool,
    /// User agent to send in http header
    #[arg(short, long, value_name = "AGENT")]
    agent: Option<String>,
    /// Coverty all words to lowercase
    #[arg(short, long)]
    lower: bool,
    /// Parses words that contains diacritics, but removes the diacritics
    #[arg(short='r', long)]
    diacrit_remove: bool,
}

fn main() {
    let _args = Cli::parse();

    let url = "https://vitejs.dev";
    let num_common_words = 300;

    match unique_words_from_url(url, num_common_words) {
        Ok(word_counts) => {
            for (word, count) in &word_counts {
                println!("{}: {}", word, count);
            }
        }
        Err(e) => eprintln!("Error: {:?}", e),
    }
}
