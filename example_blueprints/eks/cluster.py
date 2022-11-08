"""Reference blueprint for an AWS EKS cluster."""
from stackzilla.provider.aws.eks.cluster import AWSEKSCluster
from stackzilla.provider.aws.eks.node_group import AWSEKSNodeGroup

class MyCluster(AWSEKSCluster):
    """Example EKS cluster"""

    def __init__(self):
        super().__init__()

        self.name = 'zim-cluster'
        self.region = 'us-east-1'
        self.role_arn = 'arn:aws:iam::259202773377:role/eksClusterRole'
        self.subnets = ['subnet-0529b74eec9b7bb55', 'subnet-018aca8c50f90e499']
        self.k8s_version = '1.22'

class MyNodeGroup(AWSEKSNodeGroup):
    """Example EKS node group"""

    def __init__(self):
        super().__init__()

        self.name = 'zim-eks-nodegroup'
        self.cluster = MyCluster
        self.region = 'us-east-1'
        self.iam_role = 'arn:aws:iam::259202773377:role/AmazonEKSNodeRole'
        self.subnets = ['subnet-0529b74eec9b7bb55', 'subnet-018aca8c50f90e499']
