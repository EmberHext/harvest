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
use select::{
    document::Document,
    predicate::{
        Attr,
        Name,
        Predicate,
    }
};
use regex::Regex;
use select::node::Node;
use reqwest::Url;
use std::collections::HashSet;
use std::io::Write;

struct Or(Vec<Box<dyn Predicate>>);

impl Predicate for Or {
    fn matches(&self, node: &Node) -> bool {
        self.0.iter().any(|predicate| predicate.matches(node))
    }
}

fn process_node(
    node: &Node,
    base_url: &Url,
    depth: u32,
    max_depth: u32,
    word_count: &mut HashMap<String, u32>,
    visited_urls: &mut HashSet<Url>,
    common_words_limit: usize,
) {
    if depth <= max_depth {
        let link = node.attr("href").and_then(|href| base_url.join(href).ok());

        if let Some(url) = link {
            if let Ok(new_word_count) = unique_words_from_url_recursive(&url, depth + 1, max_depth, common_words_limit, visited_urls) {
                for (word, count) in new_word_count {
                    *word_count.entry(word).or_insert(0) += count;
                }
            }
        }
    }
}
fn unique_words_from_url_recursive(
    url: &Url,
    depth: u32,
    max_depth: u32,
    common_words_limit: usize,
    visited_urls: &mut HashSet<Url>,
) -> Result<HashMap<String, u32>, Box<dyn std::error::Error>> {
    if !visited_urls.insert(url.clone()) {
        // If the URL is already in the visited set, return an empty HashMap
        return Ok(HashMap::new());
    }
    let resp = reqwest::blocking::get(url.as_str())?;
    let document = Document::from_read(resp)?;
    
    let tags = vec![
        Name("h1"), Name("h2"), Name("h3"), Name("h4"), Name("h5"), Name("h6"),
        Name("p"), Name("li"), Name("dt"), Name("dd"), Name("blockquote"), Name("q"), Name("cite"),
        Name("caption"), Name("th"), Name("td"), Name("pre"), Name("code"), Name("strong"), Name("em"),
        Name("mark"), Name("small"), Name("del"), Name("ins"), Name("sub"), Name("sup"), Name("a"),
    ];

    let or_predicate = Or(tags.into_iter().map(|tag| Box::new(tag) as Box<dyn Predicate>).collect());
    let elements = document.find(or_predicate);

    let mut word_count = HashMap::new();
    let link_predicate = Attr("href", ());

    let common_words_file = File::open(Path::new("src/resources/commonwords.txt"))?;
    let common_words_reader = BufReader::new(common_words_file);
    let common_words: HashSet<_> = common_words_reader.lines().take(common_words_limit).filter_map(Result::ok).collect();

    let re = Regex::new(r"[^a-zA-Z0-9']+").unwrap();

    for node in elements {
        let text = node.text();

        for word in text.split_whitespace() {
            let cleaned_word = re.replace_all(word, "").to_lowercase();
            if !cleaned_word.is_empty() && !common_words.contains(&cleaned_word) {
                *word_count.entry(cleaned_word).or_insert(0) += 1;
            }
        }

        if depth <= max_depth {
            for link_node in node.find(link_predicate.clone()) {
                process_node(&link_node, url, depth, max_depth, &mut word_count, visited_urls, common_words_limit);
            }
        }
    }

    Ok(word_count)
}

fn unique_words_from_url(
    url: &str,
    max_depth: u32,
    common_words_limit: usize,
) -> Result<HashMap<String, u32>, Box<dyn std::error::Error>> {
    let parsed_url = Url::parse(url)?;
    let mut visited_urls = HashSet::new();
    unique_words_from_url_recursive(&parsed_url, 0, max_depth, common_words_limit, &mut visited_urls)
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
    let url = "https://vitejs.dev";
    let max_depth = 4;
    let common_words_limit = 400;
    let output_file_path = "output.txt";

    match unique_words_from_url(url, max_depth, common_words_limit) {
        Ok(word_count) => {
            let mut file = File::create(output_file_path).expect("Unable to create file");

            let mut sorted_word_count: Vec<(&String, &u32)> = word_count.iter().collect();
            sorted_word_count.sort_by(|a, b| b.1.cmp(a.1));

            for (word, count) in sorted_word_count {
                writeln!(file, "{}: {}", word, count).expect("Unable to write data");
            }

            println!("Results have been written to '{}'", output_file_path);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}