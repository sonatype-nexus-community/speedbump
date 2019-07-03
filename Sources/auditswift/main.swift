import Foundation
import ColorizeSwift

let f = try! Figlet(fontFile:"fonts/chunky.flf")
let t = f!.drawText(text: "AuditSwift")
for s in t
{
    print(s.blue())
}
