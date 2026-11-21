import AppKit
import Charts
import SwiftUI

struct SpamChart: View {
    let stats: [DailyCategoryStat]
    let categories: [Category]
    /// 0 means all time.
    let rangeDays: Int

    @State private var selectedDate: Date?

    private static let calendar: Calendar = {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        return cal
    }()

    var body: some View {
        let model = ChartModel(stats: stats, categories: categories, rangeDays: rangeDays, calendar: Self.calendar)
        Chart {
            ForEach(model.points) { point in
                BarMark(
                    x: .value("Period", point.start, unit: model.bucket.component),
                    y: .value("Blocked", point.count)
                )
                .foregroundStyle(by: .value("Category", point.series.name))
            }
            if let selected = selectedDate.flatMap(model.bucketStart(containing:)), let total = model.totals[selected], total > 0 {
                RuleMark(x: .value("Period", selected, unit: model.bucket.component))
                    .foregroundStyle(Color.secondary.opacity(0.15))
                    .zIndex(-1)
                    .annotation(position: .top, spacing: 4, overflowResolution: .init(x: .fit(to: .chart), y: .disabled)) {
                        tooltip(model: model, start: selected, total: total)
                    }
            }
        }
        .chartForegroundStyleScale(domain: model.series.map(\.name), range: model.series.map(\.color))
        .chartXScale(domain: model.domain)
        .chartXSelection(value: $selectedDate)
        .chartLegend(position: .bottom, spacing: 12)
        .frame(height: 240)
    }

    private func tooltip(model: ChartModel, start: Date, total: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(model.bucket.label(for: start, calendar: Self.calendar))
                .font(.caption.weight(.semibold))
            Text("\(total) blocked")
                .font(.caption)
                .foregroundStyle(.secondary)
            ForEach(model.breakdown(at: start), id: \.series.name) { row in
                HStack(spacing: 6) {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(row.series.color)
                        .frame(width: 8, height: 8)
                    Text(row.series.name)
                        .font(.caption)
                    Spacer(minLength: 12)
                    Text("\(row.count)")
                        .font(.caption.monospacedDigit())
                }
            }
        }
        .padding(8)
        .frame(minWidth: 180)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Picks one bar per day, week, month or year so every range shows a readable number of bars.
enum ChartBucket {
    case day, week, month, year

    var component: Calendar.Component {
        switch self {
        case .day: .day
        case .week: .weekOfYear
        case .month: .month
        case .year: .year
        }
    }

    static func forRange(days: Int, earliest: Date?, now: Date, calendar: Calendar) -> ChartBucket {
        switch days {
        case 1...31: return .day
        case 32...120: return .week
        case 121...730: return .month
        default:
            guard let earliest else { return .month }
            let spanDays = calendar.dateComponents([.day], from: earliest, to: now).day ?? 0
            if spanDays <= 120 { return .week }
            if spanDays <= 6 * 365 { return .month }
            return .year
        }
    }

    func label(for start: Date, calendar: Calendar) -> String {
        var style = Date.FormatStyle(timeZone: calendar.timeZone)
        switch self {
        case .day:
            style = style.month(.abbreviated).day().year()
            return start.formatted(style)
        case .week:
            style = style.month(.abbreviated).day()
            return "Week of \(start.formatted(style))"
        case .month:
            style = style.month(.wide).year()
            return start.formatted(style)
        case .year:
            style = style.year()
            return start.formatted(style)
        }
    }
}

struct ChartSeries: Equatable {
    let name: String
    let color: Color
    let slot: Int
}

private struct ChartPoint: Identifiable {
    let start: Date
    let series: ChartSeries
    let count: Int
    var id: String { "\(start.timeIntervalSince1970)-\(series.name)" }
}

private struct ChartModel {
    let bucket: ChartBucket
    let points: [ChartPoint]
    let series: [ChartSeries]
    let totals: [Date: Int]
    let domain: ClosedRange<Date>
    private let calendar: Calendar

    init(stats: [DailyCategoryStat], categories: [Category], rangeDays: Int, calendar: Calendar) {
        self.calendar = calendar
        let now = Date()
        let earliest = stats.map(\.parsedDate).min()
        let bucket = ChartBucket.forRange(days: rangeDays, earliest: earliest, now: now, calendar: calendar)
        self.bucket = bucket

        var counts: [Date: [String: Int]] = [:]
        var seriesByID: [String: ChartSeries] = [:]
        for stat in stats {
            let start = calendar.dateInterval(of: bucket.component, for: stat.parsedDate)?.start ?? stat.parsedDate
            counts[start, default: [:]][stat.categoryID, default: 0] += stat.count
            if seriesByID[stat.categoryID] == nil {
                seriesByID[stat.categoryID] = CategoryColors.series(for: stat.categoryID, name: stat.categoryName, categories: categories)
            }
        }

        var points: [ChartPoint] = []
        var totals: [Date: Int] = [:]
        for (start, byCategory) in counts {
            for (categoryID, count) in byCategory {
                guard let s = seriesByID[categoryID] else { continue }
                points.append(ChartPoint(start: start, series: s, count: count))
                totals[start, default: 0] += count
            }
        }
        self.points = points.sorted { ($0.start, $0.series.slot) < ($1.start, $1.series.slot) }
        self.series = seriesByID.values.sorted { ($0.slot, $0.name) < ($1.slot, $1.name) }
        self.totals = totals

        let rangeStart: Date
        if rangeDays > 0 {
            rangeStart = calendar.date(byAdding: .day, value: -(rangeDays - 1), to: now) ?? now
        } else {
            rangeStart = earliest ?? now
        }
        let first = calendar.dateInterval(of: bucket.component, for: rangeStart)?.start ?? rangeStart
        let last = calendar.dateInterval(of: bucket.component, for: now)?.end ?? now
        self.domain = first...last
    }

    func bucketStart(containing date: Date) -> Date? {
        calendar.dateInterval(of: bucket.component, for: date)?.start
    }

    func breakdown(at start: Date) -> [(series: ChartSeries, count: Int)] {
        points.filter { $0.start == start }
            .sorted { $0.count > $1.count }
            .map { ($0.series, $0.count) }
    }
}

/// Gives every category the same color in every range. Built-in categories are pinned to palette slots by ID,
/// so renaming one or changing which categories appear never repaints the others.
enum CategoryColors {
    private static let builtinSlots: [String: Int] = [
        "marketing_promotions": 0,
        "cold_sales": 1,
        "newsletters": 2,
        "crypto_gambling": 3,
        "adult_explicit": 4,
        "political_fundraising": 6,
        "phishing_scams": 7,
    ]
    private static let customSlot = 5
    private static let otherSlot = 8

    private static let light = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
    private static let dark = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"]

    static func series(for categoryID: String, name: String, categories: [Category]) -> ChartSeries {
        let slot: Int
        if let pinned = builtinSlots[categoryID] {
            slot = pinned
        } else {
            let custom = categories.filter { !$0.builtin }.sorted { $0.createdAt < $1.createdAt }
            slot = custom.first?.id == categoryID ? customSlot : otherSlot
        }
        return ChartSeries(name: name, color: color(slot: slot), slot: slot)
    }

    private static func color(slot: Int) -> Color {
        guard slot < light.count else { return Color.secondary }
        let lightColor = NSColor(hex: light[slot])
        let darkColor = NSColor(hex: dark[slot])
        return Color(nsColor: NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? darkColor : lightColor
        })
    }
}

private extension NSColor {
    convenience init(hex: String) {
        let value = UInt32(hex.dropFirst(), radix: 16) ?? 0
        self.init(
            srgbRed: CGFloat((value >> 16) & 0xFF) / 255,
            green: CGFloat((value >> 8) & 0xFF) / 255,
            blue: CGFloat(value & 0xFF) / 255,
            alpha: 1
        )
    }
}
