#!/usr/bin/env perl
# Turn espbench "RESULT key=value ..." lines into Markdown tables:
# single-core throughput per back-end, speed-up over the reference, and
# multi-core scaling efficiency.
#
#   build/native/espbench | perl scripts/bench_report.pl > docs/BENCHMARKS.md
use strict;
use warnings;

my (@single, @multi, $header);
while (my $line = <STDIN>) {
    $header = $1 if $line =~ /^#\s*(.*)/;
    next unless $line =~ /^RESULT\s+(.*)/;
    my %r = map { split /=/, $_, 2 } split ' ', $1;
    if ($r{op} eq 'encap-mt') { push @multi, \%r } else { push @single, \%r }
}
die "no RESULT lines on stdin\n" unless @single;

my %ref;
$ref{"$_->{op}/$_->{size}"} = $_->{gbps} for grep { $_->{impl} eq 'ref' } @single;

print "# Benchmarks\n\n_${header}_\n\n" if $header;
print "## Single core\n\n";
print "| op | back-end | payload (B) | Mpps | Gbit/s | cycles/byte | vs ref |\n";
print "|---|---|---:|---:|---:|---:|---:|\n";
for my $r (sort { $a->{op} cmp $b->{op} || $a->{size} <=> $b->{size} } @single) {
    my $base = $ref{"$r->{op}/$r->{size}"};
    printf "| %s | %s | %d | %.3f | %.2f | %s | %s |\n",
        $r->{op}, $r->{impl}, $r->{size}, $r->{mpps}, $r->{gbps},
        defined $r->{cpb} ? sprintf("%.2f", $r->{cpb}) : '-',
        $base ? sprintf("%.1fx", $r->{gbps} / $base) : '-';
}

if (@multi) {
    my $one = $multi[0]{gbps};
    print "\n## Multi-core encap scaling ($multi[0]{impl}, $multi[0]{size}-byte payload, one SA per thread)\n\n";
    print "| threads | Gbit/s | speed-up | efficiency |\n|---:|---:|---:|---:|\n";
    for my $r (@multi) {
        my $s = $r->{gbps} / $one;
        printf "| %d | %.2f | %.2fx | %.0f%% |\n", $r->{threads}, $r->{gbps}, $s, 100 * $s / $r->{threads};
    }
}
