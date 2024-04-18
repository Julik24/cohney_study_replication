from sec_certs.dataset.fips import FIPSDataset
import matplotlib.pyplot as plt

def get_true_positives(annotation, sample):
    return set(annotation).intersection(set(sample))

def get_false_positives(annotation, sample):
    return set(annotation).difference(set(sample))

def get_false_negatives(annotation, sample):
    return set(sample).difference(set(annotation))

def get_recall(annotation, sample):
    return len(get_true_positives(annotation, sample)) / (len(get_true_positives(annotation, sample)) + len(get_false_negatives(annotation, sample)))

def get_precision(annotation, sample):
    return len(get_true_positives(annotation, sample)) / (len(get_true_positives(annotation, sample)) + len(get_false_positives(annotation, sample)))

# Compares vendors of vulnerable products found by a method with 12 vendors from research
def get_vendors_statistics(annotation, sample, dset: FIPSDataset):
    vendors_annotation_dict = {}
    for dgst in annotation:
        cert = dset[dgst]
        if cert.manufacturer not in vendors_annotation_dict:
            vendors_annotation_dict[cert.manufacturer] = 0
        vendors_annotation_dict[cert.manufacturer] += 1
    vendors_sample_dict = {}
    for dgst in sample:
        cert = dset[dgst]
        if cert.manufacturer not in vendors_sample_dict:
            vendors_sample_dict[cert.manufacturer] = 0
        vendors_sample_dict[cert.manufacturer] += 1
    print("Reference vendors: ", sorted(vendors_sample_dict))
    print("Found vendors: ", sorted(vendors_annotation_dict))

    labels1 = list(vendors_annotation_dict.keys())
    sizes1 = list(vendors_annotation_dict.values())
    labels2 = list(vendors_sample_dict.keys())
    sizes2 = list(vendors_sample_dict.values())
    fig, axes = plt.subplots(1, 2, figsize=(20, 10))

    axes[0].pie(sizes1, labels=labels1, autopct='%1.1f%%', startangle=140)
    axes[0].set_title('Result')

    axes[1].pie(sizes2, labels=labels2, autopct='%1.1f%%', startangle=140)
    axes[1].set_title('Reference')

    axes[0].axis('equal')
    axes[1].axis('equal')
    plt.tight_layout()
    plt.show()
