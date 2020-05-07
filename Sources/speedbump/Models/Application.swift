/* 
Copyright (c) 2020 Swift Models Generated from JSON powered by http://www.json4swift.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For support, please feel free to contact me at https://www.linkedin.com/in/syedabsar

*/

import Foundation
struct Application : Codable {
	let id : String?
	let publicId : String?
	let name : String?
	let organizationId : String?
	let contactUserName : String?
	let applicationTags : [String]?

	enum CodingKeys: String, CodingKey {

		case id = "id"
		case publicId = "publicId"
		case name = "name"
		case organizationId = "organizationId"
		case contactUserName = "contactUserName"
		case applicationTags = "applicationTags"
	}

	init(from decoder: Decoder) throws {
		let values = try decoder.container(keyedBy: CodingKeys.self)
		id = try values.decodeIfPresent(String.self, forKey: .id)
		publicId = try values.decodeIfPresent(String.self, forKey: .publicId)
		name = try values.decodeIfPresent(String.self, forKey: .name)
		organizationId = try values.decodeIfPresent(String.self, forKey: .organizationId)
		contactUserName = try values.decodeIfPresent(String.self, forKey: .contactUserName)
		applicationTags = try values.decodeIfPresent([String].self, forKey: .applicationTags)
	}
}

struct Applications : Codable {
	let applications : [Application]?

	enum CodingKeys: String, CodingKey {

		case applications = "applications"
	}

	init(from decoder: Decoder) throws {
		let values = try decoder.container(keyedBy: CodingKeys.self)
		applications = try values.decodeIfPresent([Application].self, forKey: .applications)
	}

}