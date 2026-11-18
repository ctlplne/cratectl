// SPDX-License-Identifier: BUSL-1.1
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.index.reader.ChunkReader;
import org.apache.maven.index.reader.IndexReader;
import org.apache.maven.index.reader.Record;
import org.apache.maven.index.reader.RecordExpander;
import org.apache.maven.index.reader.resource.PathWritableResourceHandler;

public class MavenIndexStock {
    public static void main(String[] args) throws Exception {
        var expander = new RecordExpander();
        try (var index = new IndexReader(null, new PathWritableResourceHandler(Path.of(args[0])))) {
            if (!index.getIndexId().equals(args[1]) || index.isIncremental()
                    || !index.getChunkNames().equals(List.of("nexus-maven-repository-index.gz"))) {
                throw new IllegalStateException("Unexpected full index descriptor");
            }
            int descriptors = 0;
            int artifacts = 0;
            for (ChunkReader chunk : index) {
                try (chunk) {
                    if (chunk.getVersion() != 1 || !index.getPublishedTimestamp().equals(chunk.getTimestamp())) {
                        throw new IllegalStateException("Index properties and chunk must share a timestamp");
                    }
                    for (var raw : chunk) {
                        var record = expander.apply(raw);
                        switch (record.getType()) {
                            case DESCRIPTOR -> {
                                if (!index.getIndexId().equals(record.getString(Record.REPOSITORY_ID))) {
                                    throw new IllegalStateException("Index repository identity differs");
                                }
                                descriptors++;
                            }
                            case ARTIFACT_ADD -> {
                                if (++artifacts > 16 || record.getString(Record.CLASSIFIER) != null
                                        || !"jar".equals(record.getString(Record.PACKAGING))
                                        || !"jar".equals(record.getString(Record.FILE_EXTENSION))) {
                                    throw new IllegalStateException("Unexpected hosted JAR record");
                                }
                                System.out.println(String.join("\t", record.getString(Record.GROUP_ID),
                                        record.getString(Record.ARTIFACT_ID), record.getString(Record.VERSION),
                                        record.getString(Record.SHA_256), record.getLong(Record.FILE_SIZE).toString()));
                            }
                            default -> throw new IllegalStateException("Unexpected index record type");
                        }
                    }
                }
            }
            if (descriptors != 1) {
                throw new IllegalStateException("Exactly one repository descriptor is required");
            }
        }
    }
}
